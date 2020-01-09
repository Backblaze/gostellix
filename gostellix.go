package gostellix

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	ID              int            `json:"id,omitempty"`
	Name            string         `json:"name"`
	TypeID          int            `json:"typeId,omitempty"`
	HasGtdRegions   bool           `json:"hasGtdRegions,omitempty"`
	HasGeoIP        bool           `json:"hasGeoIP,omitempty"`
	NameserverGroup int            `json:"nameserverGroup,omitempty"`
	Nameservers     []string       `json:"nameservers,omitempty"`
	CreatedTs       string         `json:"createdTs,omitempty"`
	ModifiedTs      string         `json:"modifiedTs,omitempty"`
	Note            string         `json:"note,omitempty"`
	Version         int            `json:"version,omitempty"`
	Status          string         `json:"status,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	Soa             *ConstellixSoa `json:"soa,omitempty"`
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
	ID                 int                    `json:"id,omitempty"`
	Name               string                 `json:"name,omitempty"`
	TTL                int                    `json:"ttl,omitempty"`
	Geolocation        *GeolocationObj        `json:"geolocation,omitempty"`
	RecordOption       string                 `json:"recordOption,omitempty"`
	NoAnswer           bool                   `json:"noAnswer,omitempty"`
	Note               string                 `json:"note,omitempty"`
	GtdRegion          int                    `json:"gtdRegion,omitempty"`
	Type               string                 `json:"type,omitempty"`
	ParentID           int                    `json:"parentId,omitempty"`
	Parent             string                 `json:"parent,omitempty"`
	Source             string                 `json:"source,omitempty"`
	ContactIDs         []int                  `json:"contactIds,omitempty"`
	RoundRobin         []RoundRobinObj        `json:"roundRobin"`
	RecordFailover     *RecordFailoverObj     `json:"recordFailover,omitifempty"`
	Pools              []int                  `json:"pools,omitempty"`
	RoundRobinFailover *RoundRobinFailoverObj `json:"roundRobinFailover"`
	ModifiedTs         int                    `json:"modifiedTs,omitempty"`
	Value              []string               `json:"value,omitempty"`
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

// New Create a new client
func New(apikey, secretkey string) *Client {
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

// GetDomainByName Get a single domain, by name
func (client *Client) GetDomainByName(name string) (ConstellixDomain, error) {
	allDomains, _ := client.GetAllDomains()
	for _, domain := range allDomains {
		if domain.Name == name {
			return domain, nil
		}
	}
	return ConstellixDomain{}, errors.New("No such domain")
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

// CreateDomains Create a list of domains by name
func (client *Client) CreateDomains(domains []string) error {
	nameObj := struct {
		Names []string `json:"names"`
	}{domains}
	res, err := json.Marshal(nameObj)
	if err != nil {
		return err
	}
	jsonStr := string(res)
	_, err = client.APIRequest("v1/domains/", jsonStr, "POST")
	return err
}

// DeleteDomain delete domain, by integer id
func (client *Client) DeleteDomain(id int) error {
	_, err := client.APIRequest("v1/domains/"+strconv.Itoa(id), "", "DELETE")
	return err
}

// ModifyDomain replace existing Domain
func (client *Client) ModifyDomain(domain ConstellixDomain) error {
	res, err := json.Marshal(domain)
	jsonStr := string(res)
	_, err = client.APIRequest("v1/domains/"+strconv.Itoa(domain.ID), jsonStr, "PUT")
	return err
}

// GetRecordsByDomainName get all records for a domain, by name
func (client *Client) GetRecordsByDomainName(domainName string) ([]ConstellixRecord, error) {
	allDomains, _ := client.GetAllDomains()
	for _, domain := range allDomains {
		if domain.Name == domainName {
			return client.GetDomainRecords(domain.ID)
		}
	}
	return nil, nil
}

// GetDomainRecords get all records for one domain by domain ID
func (client *Client) GetDomainRecords(domainid int) ([]ConstellixRecord, error) {
	var records []ConstellixRecord
	body, err := client.APIRequest("v1/domains/"+strconv.Itoa(domainid)+"/records", "", "GET")
	//TODO: go through paging
	//TODO: check error
	json.Unmarshal(body, &records)
	return records, err
}

// GetDomainRecord Get one record from a domain, by ID
func (client *Client) GetDomainRecord(domainID int, recordType string, recordID int) (ConstellixRecord, error) {
	var domain ConstellixRecord
	body, err := client.APIRequest("v1/domains/"+strconv.Itoa(domainID)+"/records/"+recordType+"/"+strconv.Itoa(recordID), "", "GET")
	json.Unmarshal(body, &domain)
	return domain, err
}

// DeleteDomainRecord delete one domain record
func (client *Client) DeleteDomainRecord(domainID int, recordType string, recordID int) error {
	_, err := client.APIRequest("v1/domains/"+strconv.Itoa(domainID)+"/records/"+recordType+"/"+strconv.Itoa(recordID), "", "DELETE")
	return err
}

// CreateDomainRecord add a record to a domain
func (client *Client) CreateDomainRecord(domainID int, record ConstellixRecord) error {
	recordJSON, _ := json.Marshal(record)
	_, err := client.APIRequest("v1/domains/"+strconv.Itoa(domainID)+"/records/"+record.Type, string(recordJSON), "POST")
	return err
}

// ModifyDomainRecord add a record to a domain
func (client *Client) ModifyDomainRecord(domainID int, record ConstellixRecord) error {
	recordJSON, _ := json.Marshal(record)
	_, err := client.APIRequest("v1/domains/"+strconv.Itoa(domainID)+"/records/"+record.Type, string(recordJSON), "PUT")
	return err
}

// APIRequest make an API request
func (client *Client) APIRequest(endpoint, params, reqtype string) (response []byte, err error) {
	requrl := client.APIURL + endpoint
	var req *http.Request
	if reqtype == "PUT" || reqtype == "POST" {
		req, err = http.NewRequest(reqtype, requrl, bytes.NewBuffer([]byte(params)))
	} else if reqtype == "GET" || reqtype == "DELETE" {
		if params != "" {
			requrl += "?" + params
		}
		req, err = http.NewRequest(reqtype, requrl, nil)
	} else {
		// unknown request type
		return nil, err
	}
	req.Header.Add(authHeaderName, client.Token)
	req.Header.Add("User-Agent", client.UserAgent)
	req.Header.Add("Content-type", "application/json")
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	//TODO: handle errors.  Network failures, and maybe expired-token failures.  Or, rather, pass them up better
	//TODO: check for non-200 and pass that up as well
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, err
}
