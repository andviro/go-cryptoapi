package csp

//#include "common.h"
import "C"

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

type SimpleBlob []byte

type SessionKey struct {
	SeanceVector       []byte
	EncryptedKey       []byte
	MACKey             []byte
	EncryptionParamSet []byte
}

// type Gost28147_89Key struct{}
//
// type Gost28147_89MAC struct{}

//	Gost28147-89-EncryptedKey ::=   SEQUENCE {
//	  encryptedKey         Gost28147-89-Key,
//	  maskKey              [0] IMPLICIT Gost28147-89-Key
//	                           OPTIONAL,
//	  macKey               Gost28147-89-MAC
//	}
type Gost28147_89EncryptedKey struct {
	EncryptedKey []byte
	MaskKey      []byte `asn1:"tag:0,optional"`
	MacKey       []byte
}

type SubjectPublicKeyInfo struct {
	Algorithm             AlgorithmIdentifier
	EncapsulatedPublicKey asn1.BitString
}

type SignParams struct {
	DHParamsOID asn1.ObjectIdentifier
	DigestOID   asn1.ObjectIdentifier
}

type AlgorithmIdentifier struct {
	PublicKeyOID asn1.ObjectIdentifier
	SignParams   SignParams
}

//	GostR3410-TransportParameters ::= SEQUENCE {
//	  encryptionParamSet   OBJECT IDENTIFIER,
//	  ephemeralPublicKey   [0] IMPLICIT SubjectPublicKeyInfo OPTIONAL,
//	  ukm                  OCTET STRING
//	}
type GostR3410TransportParameters struct {
	EncryptionParamSet asn1.ObjectIdentifier
	EphemeralPublicKey SubjectPublicKeyInfo `asn1:"tag:0,optional"`
	SeanceVector       []byte
}

//	GostR3410-KeyTransport ::= SEQUENCE {
//	  sessionEncryptedKey   Gost28147-89-EncryptedKey,
//	  transportParameters
//	    [0] IMPLICIT GostR3410-TransportParameters OPTIONAL
//	}
type Gost2001KeyTransportASN1 struct {
	SessionKey          Gost28147_89EncryptedKey
	TransportParameters GostR3410TransportParameters `asn1:"tag:0,optional"`
}

type GOST2001KeyTransport [172]byte

func (s SimpleBlob) ToSessionKey() (SessionKey, error) {
	var res SessionKey
	n := int(unsafe.Offsetof(C.CRYPT_SIMPLEBLOB{}.bEncryptionParamSet))
	if len(s) < n {
		return res, fmt.Errorf("invalid blob size: %d (needed %d)", len(s), n)
	}
	sb := (*C.CRYPT_SIMPLEBLOB)(unsafe.Pointer(&s[0]))
	res.SeanceVector = C.GoBytes(unsafe.Pointer(&sb.bSV[0]), C.SEANCE_VECTOR_LEN)
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

func (s SessionKey) ToSimpleBlob() (SimpleBlob, error) {
	n := int(unsafe.Offsetof(C.CRYPT_SIMPLEBLOB{}.bEncryptionParamSet)) + len(s.EncryptionParamSet)
	res := make([]byte, n)
	sb := (*C.CRYPT_SIMPLEBLOB)(unsafe.Pointer(&res[0]))
	var encapsulatedParamset struct{ OID asn1.ObjectIdentifier }
	if _, err := asn1.UnmarshalWithParams(s.EncryptionParamSet, &encapsulatedParamset, ""); err != nil {
		return res, fmt.Errorf("unmarshaling EncryptionParamSet: %+v", err)
	}
	var aiKeyAlg C.ALG_ID
	switch encapsulatedParamset.OID.String() {
	case C.szOID_CP_GOST_R3412_2015_M:
		aiKeyAlg = C.CALG_GR3412_2015_M
	case C.szOID_CP_GOST_R3412_2015_K:
		aiKeyAlg = C.CALG_GR3412_2015_K
	default:
		aiKeyAlg = C.CALG_G28147
	}
	sb.tSimpleBlobHeader.BlobHeader.aiKeyAlg = aiKeyAlg
	sb.tSimpleBlobHeader.BlobHeader.bType = C.SIMPLEBLOB
	sb.tSimpleBlobHeader.BlobHeader.bVersion = C.BLOB_VERSION
	sb.tSimpleBlobHeader.BlobHeader.reserved = 0
	sb.tSimpleBlobHeader.EncryptKeyAlgId = C.CALG_G28147
	sb.tSimpleBlobHeader.Magic = C.SIMPLEBLOB_MAGIC
	C.memcpy(unsafe.Pointer(&sb.bSV), unsafe.Pointer(&s.SeanceVector[0]), C.ulong(len(s.SeanceVector)))
	C.memcpy(unsafe.Pointer(&sb.bEncryptedKey), unsafe.Pointer(&s.EncryptedKey[0]), C.ulong(len(s.EncryptedKey)))
	C.memcpy(unsafe.Pointer(&sb.bMacKey), unsafe.Pointer(&s.MACKey[0]), C.ulong(len(s.MACKey)))
	C.memcpy(unsafe.Pointer(&sb.bEncryptionParamSet), unsafe.Pointer(&s.EncryptionParamSet[0]), C.ulong(len(s.EncryptionParamSet)))
	return SimpleBlob(res), nil
}

func parseOID(src string) (asn1.ObjectIdentifier, error) {
	var res asn1.ObjectIdentifier
	for _, s := range strings.Split(src, ".") {
		val, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
		if err != nil {
			return nil, err
		}
		res = append(res, int(val))
	}
	return res, nil
}

func (s BlockEncryptedData) ToGOST2001KeyTransportASN1() (res Gost2001KeyTransportASN1, _ error) {
	dhoid, err := parseOID(s.DHParamsOID)
	if err != nil {
		return res, fmt.Errorf("parsing DHParamsOID: %+v", err)
	}
	digestOID, err := parseOID(s.DigestOID)
	if err != nil {
		return res, fmt.Errorf("parsing DigestOID: %+v", err)
	}
	publicKeyOID, err := parseOID(s.PublicKeyOID)
	if err != nil {
		return res, fmt.Errorf("parsing PublicKeyOID: %+v", err)
	}
	encapsulatedPubkey, err := asn1.Marshal(s.SessionPublicKey)
	if err != nil {
		return res, fmt.Errorf("marshaling SessionPublicKey: %+v", err)
	}
	res = Gost2001KeyTransportASN1{
		SessionKey: Gost28147_89EncryptedKey{EncryptedKey: s.SessionKey.EncryptedKey, MacKey: s.SessionKey.MACKey},
		TransportParameters: GostR3410TransportParameters{
			EphemeralPublicKey: SubjectPublicKeyInfo{
				Algorithm: AlgorithmIdentifier{
					PublicKeyOID: publicKeyOID,
					SignParams: SignParams{
						DHParamsOID: dhoid,
						DigestOID:   digestOID,
					},
				},
				EncapsulatedPublicKey: asn1.BitString{Bytes: encapsulatedPubkey, BitLength: len(encapsulatedPubkey) * 8},
			},
			SeanceVector: s.SessionKey.SeanceVector,
		},
	}
	var encapsulatedParamset struct{ OID asn1.ObjectIdentifier }
	if _, err := asn1.UnmarshalWithParams(s.SessionKey.EncryptionParamSet, &encapsulatedParamset, ""); err != nil {
		return res, fmt.Errorf("unmarshaling EncryptionParamSet: %+v", err)
	}
	res.TransportParameters.EncryptionParamSet = encapsulatedParamset.OID
	return res, nil
}

func (k Gost2001KeyTransportASN1) ToBlockEncryptedData(dataStream []byte) (BlockEncryptedData, error) {
	res := BlockEncryptedData{
		IV:         dataStream[0:8],
		CipherText: dataStream[8:],
		SessionKey: SessionKey{
			EncryptedKey: k.SessionKey.EncryptedKey,
			MACKey:       k.SessionKey.MacKey,
			SeanceVector: k.TransportParameters.SeanceVector,
		},
		DHParamsOID:  k.TransportParameters.EphemeralPublicKey.Algorithm.SignParams.DHParamsOID.String(),
		DigestOID:    k.TransportParameters.EphemeralPublicKey.Algorithm.SignParams.DigestOID.String(),
		PublicKeyOID: k.TransportParameters.EphemeralPublicKey.Algorithm.PublicKeyOID.String(),
	}
	_, err := asn1.Unmarshal(k.TransportParameters.EphemeralPublicKey.EncapsulatedPublicKey.Bytes, &res.SessionPublicKey)
	if err != nil {
		return res, err
	}
	encapsulatedParamset := struct{ OID asn1.ObjectIdentifier }{k.TransportParameters.EncryptionParamSet}
	if res.SessionKey.EncryptionParamSet, err = asn1.Marshal(encapsulatedParamset); err != nil {
		return res, nil
	}
	return res, nil
}
