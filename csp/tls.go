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

*/
import "C"

import (
	"fmt"
	"net"
)

// Conn encapsulates TLS connection implementing net.Conn interface
type Conn struct {
	conn  net.Conn
	creds *Credentials
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
	return
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
