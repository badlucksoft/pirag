package prjiapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jamesruan/sodium"
)

var (
	PRJI_CLIENT_ID     string
	PRJI_CLIENT_SECRET string
	PRJI_PRIVATE_KEY   string
	PRJI_SIGNING_KEY   string
	PRJI_ACCESS_TOKEN string
)

type HandshakeRequest struct {
	RequestType     string `json:"request_type"`
	ClientID        string `json:"client_id"`
	EncryptedString string `json:"encrypted"`
	EncryptionNonce string `json:"encrypt_nonce"`
	SecretSignature string `json:"secret_signature"`
}

type HandshakeResponse struct {
	Response     string `json:"response"`
	AccessToken  string `json:"access_token"`
	EncryptNonce string `json:"encrypt_nonce"`
	Signature    string `json:"signature"`
	ValidUntil   string `json:"valid_until"`
	Nonce        string `json:"nonce,omitempty"`
	Error        string `json:"error,omitempty"`
}

func PerformHandshake() {
	hsr := HandshakeRequest{RequestType: "handshake", ClientID: PRJI_CLIENT_ID}
	servkey, _ := base64.StdEncoding.DecodeString(SERVER_KEYS.EncryptPublicKey)
	privkey, _ := base64.StdEncoding.DecodeString(PRJI_PRIVATE_KEY)
	signkey, _ := base64.StdEncoding.DecodeString(PRJI_SIGNING_KEY)
	servsignkey, _ := base64.StdEncoding.DecodeString(SERVER_KEYS.SignPublicKey)
	enc := PKEncrypt([]byte(PRJI_CLIENT_SECRET), sodium.BoxPublicKey{servkey}, sodium.BoxSecretKey{privkey})
	hsr.EncryptedString = enc.Content
	hsr.EncryptionNonce = base64.StdEncoding.EncodeToString([]byte(enc.Nonce))
	var sbes sodium.Bytes
	sbes = []byte(enc.Content)
	sig := sbes.SignDetached(sodium.SignSecretKey{signkey})
	hsr.SecretSignature = base64.StdEncoding.EncodeToString(sig.Bytes)
	hsr.EncryptedString = base64.StdEncoding.EncodeToString([]byte(hsr.EncryptedString))
	hsrjson, _ := json.Marshal(hsr)
	response, err := SendAPIRequest(hsrjson)
	var hsresp HandshakeResponse
	json.Unmarshal(response, &hsresp)
	fmt.Printf("reponse from server: %v\nerr: %v\n", hsresp, err)
	atraw,err := base64.StdEncoding.DecodeString(hsresp.AccessToken)
	atnraw,err := base64.StdEncoding.DecodeString(hsresp.EncryptNonce)
	atsig,err := base64.StdEncoding.DecodeString(hsresp.Signature)
if VerifySignature(atraw,sodium.Signature{atsig},sodium.SignPublicKey{servsignkey}) {
	at,_ := PKDecrypt(atraw,atnraw,sodium.BoxPublicKey{servkey}, sodium.BoxSecretKey{privkey})
	fmt.Printf("token: %s\n",at)
	PRJI_ACCESS_TOKEN = string(at)
	} else {
		fmt.Println("signature on access token didn't match")
	}
}
