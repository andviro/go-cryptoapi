#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
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
#   include <WinCryptEx.h>
#else
#   include <stdint.h>
#   include "CSP_WinDef.h"
#   include "CSP_WinCrypt.h"
#   include "CSP_Sspi.h"
#   include "CSP_SChannel.h"
#   include "CpSSP.h"
#   include <sys/types.h>
#   if defined (_AIX) || defined (ANDROID)
#	include <fcntl.h>
#   else
#	include <sys/fcntl.h>
#   endif
#   include <sys/stat.h>
#   include <sys/socket.h>
#   include <netinet/in.h>
#   include <arpa/inet.h>
#   include <netdb.h>
#   include <errno.h>
#   include <unistd.h>
#endif

#define MY_ENC_TYPE (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#endif
