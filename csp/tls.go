package csp

/*
#include "common.h"
#define NT4_DLL_NAME TEXT("Security.dll")

static PSecurityFunctionTable g_pSSPI;

static BOOL LoadSecurityLibrary(void) {
    INIT_SECURITY_INTERFACE         pInitSecurityInterface;
#ifdef _WIN32
    g_hSecurity = LoadLibrary(NT4_DLL_NAME);
    if(g_hSecurity == NULL)
    {
        return FALSE;
    }

    pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(g_hSecurity, "InitSecurityInterfaceA");
#else
    pInitSecurityInterface=InitSecurityInterfaceA;
#endif

    if(pInitSecurityInterface == NULL) {
        return FALSE;
    }

    g_pSSPI = pInitSecurityInterface();

    if(g_pSSPI == NULL) {
        return FALSE;
    }

    return TRUE;
}

static void UnloadSecurityLibrary(void) {
#ifdef _WIN32
    FreeLibrary(g_hSecurity);
    g_hSecurity = NULL;
#endif
}


static SECURITY_STATUS AcquireCredentialsHandle_wrap(PVOID pAuthData, PCredHandle phCredential, PTimeStamp ptsExpiry) {
    return g_pSSPI->AcquireCredentialsHandleA(
                        NULL,                   // Name of principal
                        UNISP_NAME_A,           // Name of package
                        SECPKG_CRED_OUTBOUND,   // Flags indicating use
                        NULL,                   // Pointer to logon ID
                        pAuthData,          // Package specific data
                        NULL,                   // Pointer to GetKey() func
                        NULL,                   // Value to pass to GetKey()
                        phCredential,                // (out) Cred Handle
                        ptsExpiry);             // (out) Lifetime (optional)
}



static SECURITY_STATUS InitializeSecurityContext_wrap(
  PCredHandle    phCredential,
  PCtxtHandle    phContext,
  char          *pszTargetName,
  PSecBufferDesc pInput,
  PCtxtHandle    phNewContext,
  PSecBufferDesc pOutput,
  PULONG         pfContextAttr,
  PTimeStamp     ptsExpiry
) {

    ULONG fContextReq = ISC_REQ_SEQUENCE_DETECT
		| ISC_REQ_REPLAY_DETECT
		| ISC_REQ_CONFIDENTIALITY
		| ISC_RET_EXTENDED_ERROR
		| ISC_REQ_ALLOCATE_MEMORY
		| ISC_REQ_STREAM;

	return g_pSSPI->InitializeSecurityContextA( phCredential, phContext, pszTargetName, fContextReq, 0, SECURITY_NATIVE_DREP, pInput, 0, phNewContext, pOutput, pfContextAttr, ptsExpiry);
};

static SECURITY_STATUS FreeContextBuffer_wrap(void *pvContextBuffer) {
	return g_pSSPI->FreeContextBuffer(pvContextBuffer);
}
            //g_pSSPI->DeleteSecurityContext(phContext);

static void AllocateBuffers(SecBufferDesc *buf, int n) {
    buf->cBuffers = 1;
    buf->pBuffers = malloc(n * sizeof(SecBuffer));
    buf->ulVersion = SECBUFFER_VERSION;
}

static void FreeBuffers(SecBufferDesc *buf) {
    free(buf->pBuffers);
}

static SecBuffer *GetBuffer(SecBufferDesc *buf, int n) {
	return &buf->pBuffers[n];
}

*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"
)

const TlsBufferSize = 8192

// Conn encapsulates TLS connection implementing net.Conn interface
type Conn struct {
	conn       net.Conn
	creds      *Credentials
	hContext   C.CtxtHandle
	targetName *C.char
	attrs      C.ULONG
	expires    C.TimeStamp
}

// Credentials wraps security context credentials
type Credentials struct {
	schannelCred C.SCHANNEL_CRED
	hClientCreds C.CredHandle
	expires      C.TimeStamp
}

// InitTls must be called once before using TLS-related functions
func InitTls() error {
	if 0 == C.LoadSecurityLibrary() {
		return getErr("Error loading security library")
	}
	return nil
}

// DeinitTls must be called to free the underlying TLS library
func DeinitTls() {
	C.UnloadSecurityLibrary()
}

// NewCredentials initializes default credentials
func NewCredentials() (res *Credentials, err error) {
	res = new(Credentials)
	res.schannelCred.dwVersion = C.SCHANNEL_CRED_VERSION
	res.schannelCred.dwFlags |= C.SCH_CRED_NO_DEFAULT_CREDS
	res.schannelCred.dwFlags |= C.SCH_CRED_MANUAL_CRED_VALIDATION
	if stat := C.AcquireCredentialsHandle_wrap(&res.schannelCred, &res.hClientCreds, &res.expires); stat != C.SEC_E_OK {
		err = fmt.Errorf("Error acquiring credentials handle: %x", stat)
		return
	}
	return
}

func (c *Conn) clientHandshake() error {
	var (
		OutBuffer C.SecBufferDesc
	)
	C.AllocateBuffers(&OutBuffer, 1)
	defer C.FreeBuffers(&OutBuffer)

	out0 := C.GetBuffer(&OutBuffer, 0)
	out0.pvBuffer = nil
	out0.BufferType = C.SECBUFFER_TOKEN
	out0.cbBuffer = 0

	if stat := C.InitializeSecurityContext_wrap(
		&c.creds.hClientCreds,
		nil,
		c.targetName,
		nil,
		&c.hContext,
		&OutBuffer,
		&c.attrs,
		&c.expires,
	); stat != C.SEC_I_CONTINUE_NEEDED {
		return fmt.Errorf("Error initializing security context: %x", stat)
	}
	defer C.FreeContextBuffer_wrap(out0.pvBuffer)

	n, err := c.conn.Write(C.GoBytes(out0.pvBuffer, C.int(out0.cbBuffer)))
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("Could not send handshake data")
	}

	return c.mainHandshakeLoop(true)
}

func (c *Conn) mainHandshakeLoop(doRead bool) error {
	var (
		buf                 = make([]byte, TlsBufferSize)
		bufPos              int
		InBuffer, OutBuffer C.SecBufferDesc
	)
	C.AllocateBuffers(&OutBuffer, 1)
	defer C.FreeBuffers(&OutBuffer)
	out0 := C.GetBuffer(&OutBuffer, 0)

	C.AllocateBuffers(&InBuffer, 2)
	defer C.FreeBuffers(&InBuffer)
	in0 := C.GetBuffer(&InBuffer, 0)
	in1 := C.GetBuffer(&InBuffer, 1)

	for stat := C.SECURITY_STATUS(C.SEC_I_CONTINUE_NEEDED); stat == C.SEC_I_CONTINUE_NEEDED || stat == C.SEC_E_INCOMPLETE_MESSAGE || stat == C.SEC_I_INCOMPLETE_CREDENTIALS; {
		if err := func() error {
			if doRead {
				n, err := c.conn.Read(buf[bufPos:])
				if err != nil {
					return err
				}
				bufPos += n
			} else {
				doRead = true
			}

			in0.pvBuffer = unsafe.Pointer(&buf[0])
			in0.cbBuffer = C.uint(bufPos)
			in0.BufferType = C.SECBUFFER_TOKEN

			in1.pvBuffer = nil
			in1.cbBuffer = 0
			in1.BufferType = C.SECBUFFER_EMPTY

			out0.pvBuffer = nil
			out0.BufferType = C.SECBUFFER_TOKEN
			out0.cbBuffer = 0

			stat = C.InitializeSecurityContext_wrap(
				&c.creds.hClientCreds,
				nil,
				c.targetName,
				&InBuffer,
				&c.hContext,
				&OutBuffer,
				&c.attrs,
				&c.expires,
			)
			defer C.FreeContextBuffer_wrap(out0.pvBuffer)
			return nil
		}(); err != nil {
			return err
		}
	}

	return nil
}

func Client(conn net.Conn) (res *Conn, err error) {
	res = &Conn{
		conn: conn,
	}
	if res.creds, err = NewCredentials(); err != nil {
		return
	}

	return
}
