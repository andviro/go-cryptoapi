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

	return g_pSSPI->InitializeSecurityContextA(
		phCredential,
		phContext,
		pszTargetName,
		fContextReq,
		0,
		SECURITY_NATIVE_DREP,
		pInput,
		0,
		phNewContext,
		pOutput,
		pfContextAttr,
		ptsExpiry
	);
};

static SECURITY_STATUS FreeContextBuffer_wrap(SecBuffer *buf) {
	SECURITY_STATUS res = g_pSSPI->FreeContextBuffer(buf->pvBuffer);
	buf->pvBuffer = NULL;
	return res;
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

	"github.com/andviro/go-state"
	"golang.org/x/net/context"
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

	lastError           error
	inBuffer, outBuffer C.SecBufferDesc
	buf                 []byte
	handshakeExtra      []byte
	numRead             int
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

func (c *Conn) clientHandshake() (err error) {
	C.AllocateBuffers(&c.outBuffer, 1)
	defer C.FreeBuffers(&c.outBuffer)

	C.AllocateBuffers(&c.inBuffer, 2)
	defer C.FreeBuffers(&c.inBuffer)

	c.targetName = C.CString("www.cryptopro.ru")
	defer C.free(unsafe.Pointer(c.targetName))

	if c.buf == nil {
		c.buf = make([]byte, TlsBufferSize)
	}
	c.numRead = 0
	fmt.Println("handshake")
	if err = state.Run(context.Background(), c.startHandshake); err != nil {
		return
	}
	return c.lastError
}

func (c *Conn) writeToken() error {
	out0 := C.GetBuffer(&c.outBuffer, 0)
	if out0.cbBuffer == 0 || out0.pvBuffer == nil {
		fmt.Println("empty out buffer")
		return nil
	}

	fmt.Printf("writeToken: %d bytes\n", out0.cbBuffer)
	n, err := c.conn.Write(C.GoBytes(out0.pvBuffer, C.int(out0.cbBuffer)))
	if err != nil {
		return fmt.Errorf("Error sending token: %v", err)
	}
	if n == 0 {
		return fmt.Errorf("Error sending token: 0 bytes sent")
	}
	fmt.Println(n, "bytes written")
	return nil
}

func (c *Conn) startHandshake(ctx context.Context) state.Func {
	fmt.Println("startHandshake")
	out0 := C.GetBuffer(&c.outBuffer, 0)
	out0.pvBuffer = nil
	out0.BufferType = C.SECBUFFER_TOKEN
	out0.cbBuffer = 0

	in0 := C.GetBuffer(&c.inBuffer, 0)
	in0.pvBuffer = unsafe.Pointer(&c.buf[0])
	in0.cbBuffer = C.uint(c.numRead)
	in0.BufferType = C.SECBUFFER_TOKEN

	in1 := C.GetBuffer(&c.inBuffer, 1)
	in1.pvBuffer = nil
	in1.cbBuffer = 0
	in1.BufferType = C.SECBUFFER_EMPTY

	stat := C.InitializeSecurityContext_wrap(
		&c.creds.hClientCreds,
		nil,
		c.targetName,
		nil,
		&c.hContext,
		&c.outBuffer,
		&c.attrs,
		&c.expires,
	)
	defer C.FreeContextBuffer_wrap(out0)

	if stat != C.SEC_I_CONTINUE_NEEDED {
		c.lastError = fmt.Errorf("Error initializing security context: %x", stat)
		return nil
	}
	if c.lastError = c.writeToken(); c.lastError != nil {
		return nil
	}
	return c.readServerToken
}

func (c *Conn) readServerToken(ctx context.Context) state.Func {

	fmt.Println("readServerToken")
	n, err := c.conn.Read(c.buf[c.numRead:])
	if err != nil {
		c.lastError = fmt.Errorf("Error reading handshake response: %v", err)
		return nil
	}
	if n == 0 {
		c.lastError = fmt.Errorf("Error reading handshake response: 0 bytes read")
		return nil
	}
	fmt.Println(n, "bytes read")
	c.numRead += n
	fmt.Println(len(c.buf[:c.numRead]), "buffer length")

	return c.processServerToken
}

func (c *Conn) processServerToken(ctx context.Context) state.Func {
	fmt.Println("processServerToken")
	out0 := C.GetBuffer(&c.outBuffer, 0)
	in0 := C.GetBuffer(&c.inBuffer, 0)
	in0.cbBuffer = C.uint(c.numRead)
	in1 := C.GetBuffer(&c.inBuffer, 1)

	out0.pvBuffer = nil
	out0.BufferType = C.SECBUFFER_TOKEN
	out0.cbBuffer = 0

	stat := C.InitializeSecurityContext_wrap(
		&c.creds.hClientCreds,
		&c.hContext,
		c.targetName,
		&c.inBuffer,
		nil,
		&c.outBuffer,
		&c.attrs,
		&c.expires,
	)
	defer C.FreeContextBuffer_wrap(out0)

	if c.lastError = c.writeToken(); c.lastError != nil {
		return nil
	}

	switch stat {
	case C.SEC_E_INCOMPLETE_MESSAGE:
		fmt.Println("incomplete")
		return c.readServerToken
	case C.SEC_I_CONTINUE_NEEDED:
		fmt.Println("continue")
		if in1.BufferType == C.SECBUFFER_EXTRA {
			fmt.Println("extra")
			fmt.Printf("%v\n", c.buf[c.numRead-int(in1.cbBuffer):c.numRead])
			copy(c.buf, c.buf[c.numRead-int(in1.cbBuffer):c.numRead])
			c.numRead = int(in1.cbBuffer)
			return c.processServerToken
		} else {
			fmt.Println("no extra")
			c.numRead = 0
			return c.readServerToken
		}
	case C.SEC_E_OK:
		fmt.Println("ok")
		if in1.BufferType == C.SECBUFFER_EXTRA {
			c.handshakeExtra = c.buf[c.numRead-int(in1.cbBuffer) : c.numRead]
		}
		return nil
	case C.SEC_I_INCOMPLETE_CREDENTIALS:
		fmt.Println("credentials")
		c.lastError = fmt.Errorf("Handshake: invalid credentials")
		return nil
	default:
		c.lastError = fmt.Errorf("Handshake failed with code %x", stat)
		return nil
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
	err = res.clientHandshake()

	return
}
