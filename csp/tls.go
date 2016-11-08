package csp

/*
#include "common.h"
#define NT4_DLL_NAME TEXT("Security.dll")

static PSecurityFunctionTable g_pSSPI;
#ifdef _WIN32
static HMODULE g_hSecurity = NULL;
#endif

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


static SECURITY_STATUS ApplyControlToken_wrap(PCtxtHandle phContext, PSecBufferDesc pInput) {
    DWORD dwType = SCHANNEL_SHUTDOWN;

    pInput->pBuffers[0].pvBuffer   = &dwType;
    pInput->pBuffers[0].BufferType = SECBUFFER_TOKEN;
    pInput->pBuffers[0].cbBuffer   = sizeof(dwType);

    return g_pSSPI->ApplyControlToken(phContext, pInput);
}


static SECURITY_STATUS FreeCredentialsHandle_wrap(PCredHandle phCreds) {
	return g_pSSPI->FreeCredentialsHandle(phCreds);
}

static SECURITY_STATUS DeleteSecurityContext_wrap(PCtxtHandle phContext) {
	return g_pSSPI->DeleteSecurityContext(phContext);
}

static SECURITY_STATUS  EncryptMessage_wrap(PCtxtHandle    phContext, PSecBufferDesc pMessage) {
	return g_pSSPI->EncryptMessage(phContext, 0, pMessage, 0);
}

static SECURITY_STATUS QueryContextAttributes_wrap(PCtxtHandle phContext, ULONG ulAttribute, PVOID pBuffer) {
    return g_pSSPI->QueryContextAttributes(phContext, ulAttribute, pBuffer);
}

static SECURITY_STATUS DecryptMessage_wrap( PCtxtHandle    phContext, PSecBufferDesc pMessage) {
	return g_pSSPI->DecryptMessage(phContext, pMessage, 0, NULL);
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
    buf->cBuffers = n;
    buf->pBuffers = malloc(n * sizeof(SecBuffer));
    buf->ulVersion = SECBUFFER_VERSION;
}

static void FreeBuffers(SecBufferDesc *buf) {
    free(buf->pBuffers);
}

static SecBuffer *GetBuffer(SecBufferDesc *buf, int n) {
	return &buf->pBuffers[n];
}

static void setPCert(PCCERT_CONTEXT *dest, int idx, PCCERT_CONTEXT pCert) {
	dest[idx] = pCert;
}


*/
import "C"

import (
	"fmt"
	"net"
	"sync"
	"unsafe"

	"github.com/andviro/go-state"
	"golang.org/x/net/context"
)

const TlsBufferSize = 8192

// Conn encapsulates TLS connection implementing net.Conn interface
type Conn struct {
	conn net.Conn
	cfg  Config

	hMu, rMu, wMu                          sync.Mutex
	creds                                  *credentials
	hContext                               C.CtxtHandle
	targetName                             *C.char
	attrs                                  C.ULONG
	sizes                                  *C.SecPkgContext_StreamSizes
	expires                                C.TimeStamp
	handshakeCompleted                     bool
	lastError                              error
	inBuffer, outBuffer, writeMsg, readMsg C.SecBufferDesc
	buf, writeBuf, readBuf, decryptedData  []byte
	extraData                              []byte
	numRead                                int
}

type Config struct {
	Certificates []Cert
	ServerName   string
}

// credentials wraps security context credentials
type credentials struct {
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

// newCredentials initializes default credentials
func newCredentials(certs []Cert) (res *credentials, err error) {
	res = new(credentials)
	res.schannelCred.dwVersion = C.SCHANNEL_CRED_VERSION
	res.schannelCred.dwFlags |= C.SCH_CRED_NO_DEFAULT_CREDS
	res.schannelCred.dwFlags |= C.SCH_CRED_MANUAL_CRED_VALIDATION
	if len(certs) != 0 {
		res.schannelCred.paCred = (*C.PCCERT_CONTEXT)(C.malloc(C.sizeof_PCCERT_CONTEXT * C.size_t(len(certs))))
		for n, cert := range certs {
			C.setPCert(res.schannelCred.paCred, C.int(n), cert.pCert)
		}
	}
	if stat := C.AcquireCredentialsHandle_wrap(&res.schannelCred, &res.hClientCreds, (*C.SECURITY_INTEGER)&res.expires); stat != C.SEC_E_OK {
		err = fmt.Errorf("Error acquiring credentials handle: %x", uint32(stat))
		return
	}
	return
}

func (c *Conn) writeToken() error {
	out0 := C.GetBuffer(&c.outBuffer, 0)
	if out0.cbBuffer == 0 || out0.pvBuffer == nil {
		return nil
	}

	n, err := c.conn.Write(C.GoBytes(out0.pvBuffer, C.int(out0.cbBuffer)))
	if err != nil {
		return fmt.Errorf("Error sending token: %v", err)
	}
	if n == 0 {
		return fmt.Errorf("Error sending token: 0 bytes sent")
	}
	return nil
}

func (c *Conn) startHandshake(ctx context.Context) state.Func {
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
		c.lastError = fmt.Errorf("Error initializing security context: %x", uint32(stat))
		return nil
	}
	if c.lastError = c.writeToken(); c.lastError != nil {
		return nil
	}
	return c.readServerToken
}

func (c *Conn) readServerToken(ctx context.Context) state.Func {
	n, err := c.conn.Read(c.buf[c.numRead:])
	if err != nil {
		c.lastError = fmt.Errorf("Error reading handshake response: %v", err)
		return nil
	}
	if n == 0 {
		c.lastError = fmt.Errorf("Error reading handshake response: 0 bytes read")
		return nil
	}
	c.numRead += n

	return c.processServerToken
}

func (c *Conn) processServerToken(ctx context.Context) state.Func {
	out0 := C.GetBuffer(&c.outBuffer, 0)
	out0.pvBuffer = nil
	out0.BufferType = C.SECBUFFER_TOKEN
	out0.cbBuffer = 0

	in0 := C.GetBuffer(&c.inBuffer, 0)
	in0.cbBuffer = C.uint(c.numRead)
	in1 := C.GetBuffer(&c.inBuffer, 1)

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
		return c.readServerToken
	case C.SEC_I_CONTINUE_NEEDED:
		if in1.BufferType == C.SECBUFFER_EXTRA {
			copy(c.buf, c.buf[c.numRead-int(in1.cbBuffer):c.numRead])
			c.numRead = int(in1.cbBuffer)
			return c.processServerToken
		} else {
			c.numRead = 0
			return c.readServerToken
		}
	case C.SEC_E_OK:
		if in1.BufferType == C.SECBUFFER_EXTRA {
			c.extraData = c.buf[c.numRead-int(in1.cbBuffer) : c.numRead]
		}
		return nil
	case C.SEC_I_INCOMPLETE_CREDENTIALS:
		c.lastError = fmt.Errorf("Handshake: incomplete credentials")
		return nil
	default:
		c.lastError = fmt.Errorf("Handshake failed with code %x", uint32(stat))
		return nil
	}

	return nil
}

func (c *Conn) Handshake() (err error) {
	c.hMu.Lock()
	defer c.hMu.Unlock()

	if c.handshakeCompleted {
		return nil
	}
	C.AllocateBuffers(&c.outBuffer, 1)
	defer C.FreeBuffers(&c.outBuffer)

	C.AllocateBuffers(&c.inBuffer, 2)
	defer C.FreeBuffers(&c.inBuffer)

	if c.buf == nil {
		c.buf = make([]byte, TlsBufferSize)
	}
	c.numRead = 0
	if err = state.Run(context.Background(), c.startHandshake); err != nil {
		return
	}
	if c.lastError != nil {
		err = c.lastError
		return
	}

	c.sizes = (*C.SecPkgContext_StreamSizes)(C.malloc(C.sizeof_SecPkgContext_StreamSizes))
	if stat := C.QueryContextAttributes_wrap(&c.hContext, C.SECPKG_ATTR_STREAM_SIZES, c.sizes); stat != C.SEC_E_OK {
		err = fmt.Errorf("QueryContextAttributes result: %x", uint32(stat))
		return
	}
	bufLen := int(c.sizes.cbHeader + c.sizes.cbTrailer + c.sizes.cbMaximumMessage + 2048)
	c.writeBuf = make([]byte, bufLen)
	c.readBuf = make([]byte, bufLen)
	C.AllocateBuffers(&c.writeMsg, 4)
	C.AllocateBuffers(&c.readMsg, 4)

	c.numRead = 0
	c.handshakeCompleted = true
	return
}

func (c *Conn) Write(data []byte) (n int, err error) {
	if err = c.Handshake(); err != nil {
		return
	}

	c.wMu.Lock()
	defer c.wMu.Unlock()

	buf0 := C.GetBuffer(&c.writeMsg, 0)
	buf0.pvBuffer = unsafe.Pointer(&c.writeBuf[0])
	buf0.cbBuffer = C.uint(c.sizes.cbHeader)
	buf0.BufferType = C.SECBUFFER_STREAM_HEADER

	buf1 := C.GetBuffer(&c.writeMsg, 1)
	buf2 := C.GetBuffer(&c.writeMsg, 2)
	buf3 := C.GetBuffer(&c.writeMsg, 3)

	for len(data) > 0 {
		cbMessage := copy(c.writeBuf[int(c.sizes.cbHeader):int(c.sizes.cbHeader+c.sizes.cbMaximumMessage)], data)

		buf1.pvBuffer = unsafe.Pointer(&c.writeBuf[int(c.sizes.cbHeader)])
		buf1.cbBuffer = C.uint(cbMessage)
		buf1.BufferType = C.SECBUFFER_DATA

		buf2.pvBuffer = unsafe.Pointer(&c.writeBuf[int(c.sizes.cbHeader)+cbMessage])
		buf2.cbBuffer = C.uint(c.sizes.cbTrailer)
		buf2.BufferType = C.SECBUFFER_STREAM_TRAILER

		buf3.BufferType = C.SECBUFFER_EMPTY
		if stat := C.EncryptMessage_wrap(&c.hContext, &c.writeMsg); stat != C.SEC_E_OK {
			err = fmt.Errorf("Error encrypting message: %x", uint32(stat))
			return
		}
		if _, err = c.conn.Write(c.writeBuf[:int(c.sizes.cbHeader+c.sizes.cbTrailer)+cbMessage]); err != nil {
			return
		}
		n += cbMessage
		data = data[cbMessage:]
	}
	return
}

func (c *Conn) Read(b []byte) (n int, err error) {

	if err = c.Handshake(); err != nil || len(b) == 0 {
		return
	}

	c.rMu.Lock()
	defer c.rMu.Unlock()

	if len(c.decryptedData) == 0 {
		buf0 := C.GetBuffer(&c.readMsg, 0)
		buf1 := C.GetBuffer(&c.readMsg, 1)
		buf2 := C.GetBuffer(&c.readMsg, 2)
		buf3 := C.GetBuffer(&c.readMsg, 3)
	loop:
		for {
			if len(c.extraData) > 0 {
				if copy(c.readBuf[c.numRead:], c.extraData) < len(c.extraData) {
					err = fmt.Errorf("Read encrypted: extra data size is too big to read")
					return
				}
				c.numRead += len(c.extraData)
				c.extraData = nil
			} else {
				var numRead int
				if numRead, err = c.conn.Read(c.readBuf[c.numRead:]); err != nil {
					return
				} else {
					c.numRead += numRead
				}
			}
			buf0.pvBuffer = unsafe.Pointer(&c.readBuf[0])
			buf0.cbBuffer = C.uint(c.numRead)
			buf0.BufferType = C.SECBUFFER_DATA

			buf1.BufferType = C.SECBUFFER_EMPTY
			buf2.BufferType = C.SECBUFFER_EMPTY
			buf3.BufferType = C.SECBUFFER_EMPTY

			stat := C.DecryptMessage_wrap(&c.hContext, &c.readMsg)
			switch stat {
			case C.SEC_E_INCOMPLETE_MESSAGE:
				continue loop
			case C.SEC_E_OK:
				c.numRead = 0
				for i := 1; i < 4; i++ {
					buf := C.GetBuffer(&c.readMsg, C.int(i))
					switch buf.BufferType {
					case C.SECBUFFER_EXTRA:
						c.extraData = C.GoBytes(buf.pvBuffer, C.int(buf.cbBuffer))
					case C.SECBUFFER_DATA:
						c.decryptedData = C.GoBytes(buf.pvBuffer, C.int(buf.cbBuffer))
					}
				}
				break loop
			case C.SEC_I_RENEGOTIATE:
				c.numRead = 0
				err = c.Handshake()
				if err != nil {
					return
				}
				continue
			default:
				err = fmt.Errorf("Error decrypting data %x", uint32(stat))
				return
			}
		}
		n = copy(b, c.decryptedData)
		c.decryptedData = c.decryptedData[n:]
		return
	}

	return
}

func (c *Conn) disconnect() (err error) {
	c.hMu.Lock()
	defer c.hMu.Unlock()

	C.AllocateBuffers(&c.outBuffer, 1)
	defer C.FreeBuffers(&c.outBuffer)

	dwType := C.SCHANNEL_SHUTDOWN
	out0 := C.GetBuffer(&c.outBuffer, 0)
	out0.pvBuffer = unsafe.Pointer(&dwType)
	out0.BufferType = C.SECBUFFER_TOKEN
	out0.cbBuffer = C.sizeof_DWORD

	stat := C.ApplyControlToken_wrap(&c.hContext, &c.outBuffer)
	if stat < 0 {
		return fmt.Errorf("Error applying control token: %x", uint32(stat))
	}

	out0.pvBuffer = nil
	out0.BufferType = C.SECBUFFER_TOKEN
	out0.cbBuffer = 0

	stat = C.InitializeSecurityContext_wrap(
		&c.creds.hClientCreds,
		&c.hContext,
		nil,
		nil,
		nil,
		&c.outBuffer,
		&c.attrs,
		&c.expires,
	)

	defer C.FreeContextBuffer_wrap(out0)
	if stat < 0 {
		return fmt.Errorf("Error creating disconnect token: %x", uint32(stat))
	}

	if out0.cbBuffer == 0 || out0.pvBuffer == nil {
		return nil
	}

	_, err = c.conn.Write(C.GoBytes(out0.pvBuffer, C.int(out0.cbBuffer)))
	return
}

func (c *Conn) Close() error {
	defer C.free(unsafe.Pointer(c.targetName))
	defer C.FreeBuffers(&c.writeMsg)
	defer C.FreeBuffers(&c.readMsg)

	if c.creds != nil && c.creds.schannelCred.paCred != nil {
		defer C.free(unsafe.Pointer(c.creds.schannelCred.paCred))
	}
	if c.handshakeCompleted {
		defer C.free(unsafe.Pointer(c.sizes))
		if err := c.disconnect(); err != nil {
			return err
		}
		if stat := C.DeleteSecurityContext_wrap(&c.hContext); stat != 0 {
			return fmt.Errorf("DeleteSecurityContext failed with code %x", uint32(stat))
		}
	}
	if stat := C.FreeCredentialsHandle_wrap(&c.creds.hClientCreds); stat != 0 {
		return fmt.Errorf("FreeCredentialsHandle failed with code %x", uint32(stat))
	}
	return c.conn.Close()
}

func Client(conn net.Conn, config Config) (res *Conn, err error) {
	res = &Conn{
		conn:       conn,
		targetName: C.CString(config.ServerName),
	}
	if res.creds, err = newCredentials(config.Certificates); err != nil {
		return
	}
	return
}
