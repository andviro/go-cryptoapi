package csp

//#include "common.h"
import "C"

import (
	"fmt"
	"unsafe"
)

type SimpleBlob []byte

type SessionKey struct {
	SeanceKey          []byte
	EncryptedKey       []byte
	MACKey             []byte
	EncryptionParamSet []byte
}

func (s SimpleBlob) ToSessionKey() (SessionKey, error) {
	var res SessionKey
	n := int(unsafe.Offsetof(C.CRYPT_SIMPLEBLOB{}.bEncryptionParamSet))
	if len(s) < n {
		return res, fmt.Errorf("invalid blob size: %d (needed %d)", len(s), n)
	}
	sb := (*C.CRYPT_SIMPLEBLOB)(unsafe.Pointer(&s[0]))
	res.SeanceKey = C.GoBytes(unsafe.Pointer(&sb.bSV[0]), C.SEANCE_VECTOR_LEN)
	res.EncryptedKey = C.GoBytes(unsafe.Pointer(&sb.bEncryptedKey[0]), C.G28147_KEYLEN)
	res.MACKey = C.GoBytes(unsafe.Pointer(&sb.bMacKey[0]), C.EXPORT_IMIT_SIZE)
	if sb.bEncryptionParamSet[0] != 0x30 {
		return res, fmt.Errorf("unexpected ASN.1 tag in bEncryptionParamSet: %x", sb.bEncryptionParamSet[0])
	}
	tagLen := *(*C.BYTE)(unsafe.Pointer(uintptr(unsafe.Pointer(&sb.bEncryptionParamSet[0])) + 1))
	if n1 := int(tagLen) + n + 2; n1 != len(s) {
		return res, fmt.Errorf("invalid blob size: %d (needed %d)", len(s), n1)
	}
	res.EncryptionParamSet = C.GoBytes(unsafe.Pointer(&sb.bEncryptionParamSet[0]), C.int(tagLen)+2)
	return res, nil
}

func (s SessionKey) ToSimpleBlob() SimpleBlob {
	n := int(unsafe.Offsetof(C.CRYPT_SIMPLEBLOB{}.bEncryptionParamSet)) + len(s.EncryptionParamSet)
	res := make([]byte, n)
	sb := (*C.CRYPT_SIMPLEBLOB)(unsafe.Pointer(&res[0]))
	sb.tSimpleBlobHeader.BlobHeader.aiKeyAlg = C.CALG_G28147
	sb.tSimpleBlobHeader.BlobHeader.bType = C.SIMPLEBLOB
	sb.tSimpleBlobHeader.BlobHeader.bVersion = C.BLOB_VERSION
	sb.tSimpleBlobHeader.BlobHeader.reserved = 0
	sb.tSimpleBlobHeader.EncryptKeyAlgId = C.CALG_G28147
	sb.tSimpleBlobHeader.Magic = C.G28147_MAGIC
	C.memcpy(unsafe.Pointer(&sb.bSV), unsafe.Pointer(&s.SeanceKey[0]), C.ulong(len(s.SeanceKey)))
	C.memcpy(unsafe.Pointer(&sb.bEncryptedKey), unsafe.Pointer(&s.EncryptedKey[0]), C.ulong(len(s.EncryptedKey)))
	C.memcpy(unsafe.Pointer(&sb.bMacKey), unsafe.Pointer(&s.MACKey[0]), C.ulong(len(s.MACKey)))
	C.memcpy(unsafe.Pointer(&sb.bEncryptionParamSet), unsafe.Pointer(&s.EncryptionParamSet[0]), C.ulong(len(s.EncryptionParamSet)))
	return SimpleBlob(res)
}
