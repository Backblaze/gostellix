package gostellix

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
const defaultUserAgent string = "gostellix/0.1"

type ConstellixSoa struct {
	PrimaryNameserver string `json:"primaryNameserver,omitempty"`
	Email string `json:"email,omitempty"`
	Ttl int `json:"ttl,omitempty"`
	Serial int `json:"serial,omitempty"`
	Refresh int `json:"refresh,omitempty"`
	Retry int `json:"retry,omitempty"`
	Expire int `json:"expire,omitempty"`
	NegCache int `json:"negCache,omitempty"`
}
type ConstellixDomain struct {
	Id int `json:"id,omitempty"`
	Name string `json:"name"`
	TypeId int `json:"typeId,omitempty"`
	HasGtdRegions bool `json:"hasGtdRegions,omitempty"`
	HasGeoIP bool `json:"hasGeoIP,omitempty"`
	NameserverGroup int `json:"nameserverGroup,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	CreatedTs string `json:"createdTs,omitempty"`
	ModifiedTs string `json:"modifiedTs,omitempty"`
	Note string `json:"note,omitempty"`
	Version int `json:"version,omitempty"`
	Status string `json:"status,omitempty"`
	Tags []string `json:"tags,omitempty"`
	Soa ConstellixSoa `json:"soa,omitempty"`
}

type RoundRobinObj struct {
	Value string `json:"value"`
	Level string `json:"level,omitifempty"` // for MX records
	DisableFlag bool `json:"disableFlag"`
}
type GeolocationObj struct {
	GeoipUserRegion []int `json:"geoipUserRegion,omitempty"`
	Drop bool `json:"drop,omitifempty"`
}
type RecordFailoverValues struct {
	Value string `json:"value"`
	CheckId string `json:"checkId"`
	DisableFlag string `json:"disableFlag"`
}
type RecordFailoverObj struct {
	FailoverType int `json:"failoverType"`
	Values []RecordFailoverValues `json:"values"`
	DisableFlag bool `json:"disableFlag"`
}
type RoundRobinFailoverObjValues struct {
	Value string `json:"value"`
	DisableFlag bool `json:"disableFlag"`
	CheckId int `json:"checkId"`
}
type RoundRobinFailoverObj struct {
	Values []RoundRobinFailoverObjValues `json:"values"`
	DisableFlag bool `json:"disableFlag"`
}
type ConstellixRecord struct {
	Id int `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Ttl int `json:"ttl,omitempty"`
	Geolocation GeolocationObj `json:"geolocation,omitempty"`
	RecordOption string `json:"recordOption,omitempty"`
	NoAnswer bool `json:"noAnswer,omitempty"`
	Note string `json:"note,omitempty"`
	GtdRegion int `json:"gtdRegion,omitempty"`
	Type string `json:"type,omitempty"`
	ParentId int `json:"parentId,omitempty"`
	Parent string `json:"parent,omitempty"`
	Source string `json:"source,omitempty"`
	ContactIds []int `json:"contactIds,omitempty"`
	RoundRobin []RoundRobinObj `json:"roundRobin"`
	RecordFailover RecordFailoverObj  `json:"recordFailover,omitifempty"`
	Pools []int `json:"pools,omitempty"`
	RoundRobinFailover RoundRobinFailoverObj `json:"roundRobinFailover"`
	ModifiedTs int `json:"modifiedTs,omitempty"`
	Value []string `json:"value,omitempty"`
}

type Client struct {
	ApiURL string
	Token string
	UserAgent string
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
		UserAgent: defaultUserAgent,
	}
}

func (client *Client) GetAllDomains() ([]ConstellixDomain, error) {
	var domains []ConstellixDomain
	body, _ := client.ApiRequest("v1/domains", "", "GET")
	json.Unmarshal(body, &domains)
	return domains, nil
}

func (client *Client) ListDomains() ([]string, error) {
	var domainList []string
	domainObjects, _ := client.GetAllDomains()
	for _, domain := range domainObjects {
		domainList = append(domainList, domain.Name)
	}
	return domainList, nil
}

func (client *Client) GetDomain(domainid int) ([]ConstellixRecord, error) {
	var records []ConstellixRecord
	body, _ := client.ApiRequest("v1/domains/" + strconv.Itoa(domainid) + "/records", "", "GET")
	//TODO: go through paging
	json.Unmarshal(body, &records)
	return records, nil
}

func (client *Client) GetRecordsByDomainName(domainName string) ([]ConstellixRecord, error) {
	allDomains,_ := client.GetAllDomains()
	for _, domain := range allDomains {
		if domain.Name == domainName {
			return client.GetDomain(domain.Id)
		}
	}
	return nil,nil
}


func (client *Client) ApiRequest(endpoint, params,reqtype string) (response []byte, err error) {
	requrl := client.ApiURL + endpoint
	if params != "" {
	   requrl += "?" + params
	}
	req, err := http.NewRequest(reqtype, requrl, nil)
	req.Header.Add(authHeaderName, client.Token)
	req.Header.Add("User-Agent", client.UserAgent)
	resp, err := client.HttpClient.Do(req)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	//TODO: handle errors.  Network failures, and maybe expired-token failures.
	return body, err
}
