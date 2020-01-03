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

const defaultAPIURL string = "https://api.dns.constellix.com/"
const authHeaderName string = "x-cns-security-token"
const defaultUserAgent string = "gostellix/0.1"

// ConstellixSoa holds SOA records
type ConstellixSoa struct {
	PrimaryNameserver string `json:"primaryNameserver,omitempty"`
	Email             string `json:"email,omitempty"`
	TTL               int    `json:"ttl,omitempty"`
	Serial            int    `json:"serial,omitempty"`
	Refresh           int    `json:"refresh,omitempty"`
	Retry             int    `json:"retry,omitempty"`
	Expire            int    `json:"expire,omitempty"`
	NegCache          int    `json:"negCache,omitempty"`
}

// ConstellixDomain holds a domain
type ConstellixDomain struct {
	ID              int           `json:"id,omitempty"`
	Name            string        `json:"name"`
	TypeID          int           `json:"typeId,omitempty"`
	HasGtdRegions   bool          `json:"hasGtdRegions,omitempty"`
	HasGeoIP        bool          `json:"hasGeoIP,omitempty"`
	NameserverGroup int           `json:"nameserverGroup,omitempty"`
	Nameservers     []string      `json:"nameservers,omitempty"`
	CreatedTs       string        `json:"createdTs,omitempty"`
	ModifiedTs      string        `json:"modifiedTs,omitempty"`
	Note            string        `json:"note,omitempty"`
	Version         int           `json:"version,omitempty"`
	Status          string        `json:"status,omitempty"`
	Tags            []string      `json:"tags,omitempty"`
	Soa             ConstellixSoa `json:"soa,omitempty"`
}

// RoundRobinObj holds RoundRobin records from a domain
type RoundRobinObj struct {
	Value       string `json:"value"`
	Level       string `json:"level,omitifempty"` // for MX records
	DisableFlag bool   `json:"disableFlag"`
}

// GeolocationObj geolocation info
type GeolocationObj struct {
	GeoipUserRegion []int `json:"geoipUserRegion,omitempty"`
	Drop            bool  `json:"drop,omitifempty"`
}

// RecordFailoverValues Failover values
type RecordFailoverValues struct {
	Value       string `json:"value"`
	CheckID     string `json:"checkId"`
	DisableFlag string `json:"disableFlag"`
}

// RecordFailoverObj Failover info
type RecordFailoverObj struct {
	FailoverType int                    `json:"failoverType"`
	Values       []RecordFailoverValues `json:"values"`
	DisableFlag  bool                   `json:"disableFlag"`
}

// RoundRobinFailoverObjValues RR Failover values
type RoundRobinFailoverObjValues struct {
	Value       string `json:"value"`
	DisableFlag bool   `json:"disableFlag"`
	CheckID     int    `json:"checkId"`
}

// RoundRobinFailoverObj RR Failover Info
type RoundRobinFailoverObj struct {
	Values      []RoundRobinFailoverObjValues `json:"values"`
	DisableFlag bool                          `json:"disableFlag"`
}

// ConstellixRecord domain record
type ConstellixRecord struct {
	ID                 int                   `json:"id,omitempty"`
	Name               string                `json:"name,omitempty"`
	TTL                int                   `json:"ttl,omitempty"`
	Geolocation        GeolocationObj        `json:"geolocation,omitempty"`
	RecordOption       string                `json:"recordOption,omitempty"`
	NoAnswer           bool                  `json:"noAnswer,omitempty"`
	Note               string                `json:"note,omitempty"`
	GtdRegion          int                   `json:"gtdRegion,omitempty"`
	Type               string                `json:"type,omitempty"`
	ParentID           int                   `json:"parentId,omitempty"`
	Parent             string                `json:"parent,omitempty"`
	Source             string                `json:"source,omitempty"`
	ContactIDs         []int                 `json:"contactIds,omitempty"`
	RoundRobin         []RoundRobinObj       `json:"roundRobin"`
	RecordFailover     RecordFailoverObj     `json:"recordFailover,omitifempty"`
	Pools              []int                 `json:"pools,omitempty"`
	RoundRobinFailover RoundRobinFailoverObj `json:"roundRobinFailover"`
	ModifiedTs         int                   `json:"modifiedTs,omitempty"`
	Value              []string              `json:"value,omitempty"`
}

// Client Client for the Constellix API
type Client struct {
	APIURL     string
	Token      string
	UserAgent  string
	HTTPClient *http.Client
}

func buildSecurityToken(apikey, secretkey string) string {
	millis := time.Now().UnixNano() / 1000000
	timestamp := strconv.FormatInt(millis, 10)
	mac := hmac.New(sha1.New, []byte(secretkey))
	mac.Write([]byte(timestamp))
	hmacstr := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return apikey + ":" + hmacstr + ":" + timestamp
}

// NewClient Create a new client
func NewClient(apikey, secretkey string) *Client {
	return &Client{
		APIURL:     defaultAPIURL,
		Token:      buildSecurityToken(apikey, secretkey),
		HTTPClient: http.DefaultClient,
		UserAgent:  defaultUserAgent,
	}
}

// GetAllDomains get all domains on the acct
func (client *Client) GetAllDomains() ([]ConstellixDomain, error) {
	var domains []ConstellixDomain
	body, _ := client.APIRequest("v1/domains", "", "GET")
	json.Unmarshal(body, &domains)
	return domains, nil
}

// ListDomains get a bare list of all domain names
func (client *Client) ListDomains() ([]string, error) {
	var domainList []string
	domainObjects, _ := client.GetAllDomains()
	for _, domain := range domainObjects {
		domainList = append(domainList, domain.Name)
	}
	return domainList, nil
}

// GetDomain get one domain by ID
func (client *Client) GetDomain(domainid int) ([]ConstellixRecord, error) {
	var records []ConstellixRecord
	body, _ := client.APIRequest("v1/domains/"+strconv.Itoa(domainid)+"/records", "", "GET")
	//TODO: go through paging?  Might not need to
	json.Unmarshal(body, &records)
	return records, nil
}

// GetRecordsByDomainName get all records for a domain, by name
func (client *Client) GetRecordsByDomainName(domainName string) ([]ConstellixRecord, error) {
	allDomains, _ := client.GetAllDomains()
	for _, domain := range allDomains {
		if domain.Name == domainName {
			return client.GetDomain(domain.ID)
		}
	}
	return nil, nil
}

// APIRequest make an API request
func (client *Client) APIRequest(endpoint, params, reqtype string) (response []byte, err error) {
	requrl := client.APIURL + endpoint
	if params != "" {
		requrl += "?" + params
	}
	req, err := http.NewRequest(reqtype, requrl, nil)
	req.Header.Add(authHeaderName, client.Token)
	req.Header.Add("User-Agent", client.UserAgent)
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	//TODO: handle errors.  Network failures, and maybe expired-token failures.
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, err
}
