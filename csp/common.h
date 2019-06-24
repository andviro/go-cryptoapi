#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#   define BOOL WINBOOL 
#   include <windows.h>
#   include <wincrypt.h>
#   include <winerror.h>
typedef struct _CMSG_CTRL_DECRYPT_PARA_OVERRIDE {
    DWORD cbSize;
    HCRYPTPROV hCryptProv;
    DWORD dwKeySpec;
    DWORD dwRecipientIndex;
} CMSG_CTRL_DECRYPT_PARA_OVERRIDE,*PCMSG_CTRL_DECRYPT_PARA_OVERRIDE;
#define CMSG_CTRL_DECRYPT_PARA CMSG_CTRL_DECRYPT_PARA_OVERRIDE
#else
#   define HCRYPTPROV_OR_NCRYPT_KEY_HANDLE HCRYPTPROV
#   include <CSP_WinDef.h>
#   include <CSP_WinCrypt.h>
#endif
#include <WinCryptEx.h>

#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define ENCRYPT_OID szOID_CP_GOST_28147
#endif
