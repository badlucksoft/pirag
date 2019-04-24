package prjiapi

import (
	"bytes"
	//"crypto/tls"
	"io/ioutil"
	"net/http"
	"encoding/json"
	"encoding/base64"
	"github.com/jamesruan/sodium"
	//"errors"
)

type AccessToken struct {
	Token     string `json:"token"`
	Signature string `json:"signature"`
}

type Report struct {
	ID string `json:"id"`
	IPAddress string `json:"ip"`
	Username string `json:"username,omitempty"`
	Timestamp string `json:"timestamp"`
	URI string `json:"uri,omitempty"`
	Referrer string `json:"referrer,omitempty"`
	ReferrerEncoded bool `json:"referrer_encoded,omitempty"`
	Post string `json:"post,omitempty"`
	PostEncoded bool `json:"post_encoded,omitempty"`
	Get string `json:"get,omitempty"`
	GetEncoded bool `json:"get_encoded,omitempty"`
	Cookie string `json:"cookie,omitempty"`
	CookieEncoded bool `json:"cookie_encoded,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	UserAgentEncoded bool `json:"user_agent_encoded,omitempty"`
}
type ReportResult struct {
	ID string `json:"id"`
	Success bool `json:"success"`
	Error string `json:"error,omitempty"`
}
var (
	//PRJI_ACCESS_TOKEN AccessToken
)

type AttackReport struct {
	RequestType     string        `json:"request_type"`
	Token AccessToken `json:"access_token"`
	ReportSignature string        `json:"report_signature"`
	Reports         EncryptedData `json:"reports"`
}
type AttackReportResult struct {
	EncryptedContent string `json:"encrypted_content"`
	EncryptNonce string `json:"encrypt_nonce"`
}
type AttackReportResponse struct {
	Response string `json:"response"`
	Result AttackReportResult `json:"result,omitempty"`
	ResultSignature string `json:"result_signature,omitempty"`
	Message string `json:"message,omitempty"`
}
func SendAttackReport(request_type string, reports []Report) ([]byte,error) {
	reportsJSON, err := json.Marshal(reports)
	var data []byte
	if err == nil {
		servkey, _ := base64.StdEncoding.DecodeString(SERVER_KEYS.EncryptPublicKey)
		privkey, _ := base64.StdEncoding.DecodeString(PRJI_PRIVATE_KEY)
		signkey, _ := base64.StdEncoding.DecodeString(PRJI_SIGNING_KEY)
		areport := AttackReport{RequestType: request_type}
		encRep := PKEncrypt(reportsJSON, sodium.BoxPublicKey{servkey}, sodium.BoxSecretKey{privkey})
		areport.Reports.Content = base64.StdEncoding.EncodeToString([]byte(encRep.Content))
		areport.Reports.Nonce = base64.StdEncoding.EncodeToString([]byte(encRep.Nonce))
		areport.ReportSignature = base64.StdEncoding.EncodeToString(sodium.Bytes([]byte(encRep.Content)).SignDetached(sodium.SignSecretKey{signkey}).Bytes)
		areport.Token.Token = PRJI_ACCESS_TOKEN
		areport.Token.Signature = base64.StdEncoding.EncodeToString(sodium.Bytes([]byte(PRJI_ACCESS_TOKEN)).SignDetached(sodium.SignSecretKey{signkey}).Bytes)
		reportJSON,err := json.Marshal(areport)
		if err == nil {
			return SendAPIRequest(reportJSON)
		}
	}
	return data, err
}
func SendAPIRequest(APIRequest []byte) ([]byte, error) {
	//http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	resp, err := http.Post("https://www.prjindigo.com/api/0/", "application/json", bytes.NewBuffer(APIRequest))
	if err != nil {

		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, nil
}
