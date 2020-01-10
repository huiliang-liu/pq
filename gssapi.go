// +build linux,cgo darwin,cgo

package pq

import (
	"fmt"
	"os"

	"github.com/greenplum-db/gssapi"
)

type gssctx struct {
	//GSS related
	krbsrvname string
	pghost     string
	gsslib     *gssapi.Lib
	gctx       *gssapi.CtxId
	gtargName  *gssapi.Name
	guserName  *gssapi.Name
	ginbuf     *gssapi.Buffer
	goutbuf    *gssapi.Buffer
}

var dbgLogEnabled bool = false

func dbglog(a ...interface{}) {
	if dbgLogEnabled {
		fmt.Println(a...)
	}
}

func dbgdump(f string, a interface{}) error {
	file, err := os.Create(f)
	if err != nil {
		return err
	}
	defer file.Close()
	fmt.Fprintln(file, a)
	return nil
}

func (cn *conn) gss(o values) {
	cn.krbsrvname = o["krbsrvname"]
	cn.pghost = o["host"]
	opt := &gssapi.Options{LoadDefault: gssapi.MIT}
	dbg, ok := o["gssdebug"]
	if ok && dbg == "true" {
		dbgLogEnabled = true
		delete(o, "gssdebug")
	}
	var err error
	cn.gsslib, err = gssapi.Load(opt)
	if err != nil {
		cn.gsslib = nil
		panic(fmt.Errorf("Failed to load GSSAPI library: " + err.Error()))
	}
}

func (cn *conn) gssStartup(user string) {
	dbglog("gssStartup:", user)
	// check host
	if len(cn.pghost) == 0 {
		errorf("host name must be specified")
	}
	// check gctx
	if cn.gctx != nil {
		errorf("duplicate GSS authentication request")
	}
	// import name
	nameBuf, err := cn.gsslib.MakeBufferString(fmt.Sprintf("%s@%s", cn.krbsrvname, cn.pghost))
	defer nameBuf.Release()
	cn.gtargName, err = nameBuf.Name(cn.gsslib.GSS_C_NT_HOSTBASED_SERVICE)
	if err != nil {
		errorf("GSSAPI name import error")
	}
	userBuf, err := cn.gsslib.MakeBufferString(user)
	defer userBuf.Release()
	cn.guserName, err = userBuf.Name(cn.gsslib.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		errorf("GSSAPI user name import error")
	}
	cn.gctx = cn.gsslib.GSS_C_NO_CONTEXT
	cn.gssContinue()
}

func (cn *conn) gssContinue() {
	dbglog("gssContinue")
	//Init GSS context
	var inbuf *gssapi.Buffer
	if cn.gctx == cn.gsslib.GSS_C_NO_CONTEXT {
		inbuf = cn.gsslib.GSS_C_NO_BUFFER
	} else {
		inbuf = cn.ginbuf
	}
	cred, actualMechs, _, err := cn.gsslib.AcquireCred(cn.guserName, gssapi.GSS_C_INDEFINITE, cn.gsslib.GSS_C_NO_OID_SET, gssapi.GSS_C_BOTH)
	dbglog("cn.gsslib.AcquireCred:", cred, actualMechs, err)
	actualMechs.Release()
	if cred == nil {
		cred = cn.gsslib.GSS_C_NO_CREDENTIAL
	}
	cn.gctx, _, cn.goutbuf, _, _, err = cn.gsslib.InitSecContext(
		cred,
		nil,
		cn.gtargName,
		cn.gsslib.GSS_C_NO_OID,
		0,
		0,
		cn.gsslib.GSS_C_NO_CHANNEL_BINDINGS,
		inbuf)
	dbglog("cn.gsslib.InitSecContext:", cn.gctx, err)
	if cn.goutbuf != nil {
		err = dbgdump("goutbuf.bin", cn.goutbuf)
		if err == nil {
			dbglog("Content of cn.goutbuf is dumped to cn.goutbuf.bin")
		} else {
			dbglog(err)
		}
	}
	if cn.gctx != cn.gsslib.GSS_C_NO_CONTEXT {
		cn.ginbuf.Release()
	}
	cred.Release()

	if cn.goutbuf.Length() != 0 {
		dbglog("Send packet: ", cn.goutbuf.Length())
		// Send packet
		w := cn.writeBuf('p')
		w.kstring(cn.goutbuf.String())
		cn.send(w)
		t, r := cn.recv()
		if t != 'R' {
			errorf("unexpected gss response: %q", t)
		}

		if r.int32() != 0 {
			errorf("unexpected authentication response: %q", t)
		}
	}

	if err != nil {
		e, ok := err.(*gssapi.Error)
		if ok && !e.Major.ContinueNeeded() {
			cn.gtargName.Release()
			cn.gctx.Release()
			errorf("GSSAPI continuation error: %s", e.Error())
		}
	}
	cn.goutbuf.Release()
}
