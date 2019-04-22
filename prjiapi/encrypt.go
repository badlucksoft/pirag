package prjiapi

import (
	"github.com/jamesruan/sodium"
	//"encoding/base64"
	//"C"
	//"fmt"
)

/*
	Structure housing encrypted data
*/
type EncryptedData struct {
	Content string `json:"encrypted_content"`
	Nonce   string `json:"encrypt_nonce"`
}

/*
	Uses public-key encryption to encrypt data.
*/
func PKEncrypt(data sodium.Bytes, receiverPublicKey sodium.BoxPublicKey, senderPrivateKey sodium.BoxSecretKey) EncryptedData {
	var ed EncryptedData
	nonce := sodium.BoxNonce{}
	sodium.Randomize(&nonce)
	nonce.Next()
	ed.Content = string(data.Box(nonce, receiverPublicKey, senderPrivateKey))
	ed.Nonce = string(nonce.Bytes)
	return ed
}

/*
	Uses public-key encryption to decrypt data.
*/
func PKDecrypt(data EncryptedData, senderPublicKey sodium.BoxPublicKey, receiverPrivateKey sodium.BoxSecretKey) []byte {
	return nil
}

/*
	Verifies signature of encrypted data.
*/
func VerifySignature(data sodium.Bytes, signature sodium.Signature, signing_key sodium.SignPublicKey) bool {
	var verified = false
	err := data.SignVerifyDetached(signature, signing_key)
	if err == nil {
		verified = true
	}
	return verified
}
