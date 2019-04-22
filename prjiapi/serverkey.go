package prjiapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jamesruan/sodium"
)

type ServerKeyRequest struct {
	RequestType string `json:"request_type"`
}

type ServerKeyResponse struct {
	Response                  string `json:"response"`
	EncryptPublicKey          string `json:"encrypt_public"`
	EncryptPublicKeyHash      string `json:"encrypt_public_key_hash"`
	SignPublicKey             string `json:"sign_public"`
	SignPublicKeyHash         string `json:"sign_public_key_hash"`
	EncryptPublicKeySignature string `json:"encrypt_public_key_signature"`
	SignPublicKeySignature    string `json:"sign_public_key_signature"`
}

var (
	SERVER_KEYS ServerKeyResponse
)

func GetServerKeys() ServerKeyResponse {
	skreq := ServerKeyRequest{"getServerPK"}
	apiReq, _ := json.Marshal(skreq)
	apiResp, _ := SendAPIRequest(apiReq)
	fmt.Printf("PerformHandshake: response from server: %s\n", string(apiResp))
	json.Unmarshal(apiResp, &SERVER_KEYS)
	return SERVER_KEYS
}

func VerifyServerKey(sk ServerKeyResponse) bool {
	var verified = false
	encrypt_public, _ := base64.StdEncoding.DecodeString(sk.EncryptPublicKey)
	sign_public, _ := base64.StdEncoding.DecodeString(sk.SignPublicKey)
	epsig, _ := base64.StdEncoding.DecodeString(sk.EncryptPublicKeySignature)
	spsig, _ := base64.StdEncoding.DecodeString(sk.SignPublicKeySignature)
	if VerifySignature(sign_public, sodium.Signature{spsig}, sodium.SignPublicKey{sign_public}) {
		if VerifySignature(encrypt_public, sodium.Signature{epsig}, sodium.SignPublicKey{sign_public}) {
			verified = true
		}
	}
	return verified
}
