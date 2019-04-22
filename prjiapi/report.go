package prjiapi

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	//"errors"
)

type AccessToken struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

var (
	PRJI_ACCESS_TOKEN AccessToken
)

type AttackReport struct {
	RequestType     string        `json:"request_type"`
	ReportSignature string        `json:"report_signature"`
	Reports         EncryptedData `json:"reports"`
}

func SendAPIRequest(APIRequest []byte) ([]byte, error) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Post("https://www.prjindigo.com/api/0/", "application/json", bytes.NewBuffer(APIRequest))
	if err != nil {

		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, nil
}
