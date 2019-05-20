#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#   define BOOL WINBOOL 
#   include <windows.h>
#   include <winsock.h>
#   include <wincrypt.h>
#   include <wintrust.h>
#   include <schannel.h>
#   include <time.h>
#   define SECURITY_WIN32
#   include <security.h>
#   include <sspi.h>
#   define IS_SOCKET_ERROR(a) (a==SOCKET_ERROR)
#   include <winerror.h>
#   include <sys/types.h>
#else
#   define HCRYPTPROV_OR_NCRYPT_KEY_HANDLE HCRYPTPROV
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#   include "CSP_Sspi.h"
#   include "CSP_SChannel.h"
#endif

#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#endif
