package constellix

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

const defaultApiURL string = "https://api.dns.constellix.com/"
const authHeaderName string = "x-cns-security-token"

type constellixSoa struct {
	PrimaryNameserver string
	Email string
	Ttl int
	Serial int
	Refresh int
	Retry int
	Expire int
	NegCache int
}
type constellixDomain struct {
	Id int
	Name string
	Soa constellixSoa
	CreatedTs string
	ModifiedTs string
	HasGeoIP bool
	Nameservers []string
	Status string
}
type constellixRecord struct {
	Id int
	Type string
	RecordType string
	Name string
	RecordOption string
	NoAnswer bool
	Note string
	Ttl int
	GtdRegion int
	ParentId string
	Parent string
	Source string
	ModifiedTs int
	value []string
}

type Client struct {
	ApiURL string
	Token string
	HttpClient *http.Client
}

func buildSecurityToken(apikey, secretkey string ) string {
	millis := time.Now().UnixNano() / 1000000
	timestamp := strconv.FormatInt(millis, 10)
	mac := hmac.New(sha1.New, []byte(secretkey))
	mac.Write([]byte(timestamp))
	hmacstr := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return apikey + ":" + hmacstr + ":" + timestamp
}

func NewClient(apikey, secretkey string) *Client {
	return &Client{
		ApiURL: defaultApiURL,
		Token: buildSecurityToken(apikey, secretkey),
		HttpClient:  http.DefaultClient,
	}
}

func (client *Client) GetAllDomains() ([]constellixDomain, error) {
	var domains []constellixDomain
	body, _ := client.ApiRequest("v1/domains", "", "GET")
	json.Unmarshal(body, &domains)
	return domains, nil
}

func (client *Client) GetDomain(domainid int) ([]constellixRecord, error) {
	var records []constellixRecord
	body, _ := client.ApiRequest("v1/domains/" + strconv.Itoa(domainid) + "/records", "", "GET")
	json.Unmarshal(body, &records)
	return records, nil
}


func (client *Client) ApiRequest(endpoint, params,reqtype string) (response []byte, err error) {
	requrl := client.ApiURL + endpoint
	if params != "" {
	   requrl += "?" + params
	}
	req, err := http.NewRequest(reqtype, requrl, nil)
	//TODO: set UserAgent
	req.Header.Add(authHeaderName, client.Token)
	resp, err := client.HttpClient.Do(req)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	//TODO: handle errors.  Network failures, and maybe expired-token failures.
	return body, err
}
