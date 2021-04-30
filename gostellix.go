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
	ID              int            `json:"id"`
	Name            string         `json:"name"`
	TypeID          int            `json:"typeId,omitempty"`
	HasGtdRegions   bool           `json:"hasGtdRegions,omitempty"`
	HasGeoIP        bool           `json:"hasGeoIP,omitempty"`
	NameserverGroup int            `json:"nameserverGroup,omitempty"`
	Nameservers     []string       `json:"nameservers,omitempty"`
	CreatedTs       time.Time      `json:"createdTs,omitempty"`
	ModifiedTs      time.Time      `json:"modifiedTs,omitempty"`
	Note            string         `json:"note,omitempty"`
	Version         int            `json:"version,omitempty"`
	Status          string         `json:"status,omitempty"`
	Tags            []string       `json:"tags,omitempty"`
	Soa             *ConstellixSoa `json:"soa,omitempty"`
}

// RoundRobinObj holds RoundRobin records from a domain
type RoundRobinObj struct {
	Value       string `json:"value"`
	Level       int    `json:"level,omitempty"` // for MX records
	DisableFlag bool   `json:"disableFlag"`
}

// GeolocationObj geolocation info
type GeolocationObj struct {
	GeoipUserRegion []int `json:"geoipUserRegion,omitempty"`
	Drop            bool  `json:"drop,omitempty"`
	GeoipFailover   bool  `json:"geoipFailover,omitempty"`
	GeoipProximity  int   `json:"geoipProximity,omitempty"`
}

// RecordFailoverValues Failover values
type RecordFailoverValues struct {
	Value       string `json:"value"`
	CheckID     int    `json:"checkId"`
	DisableFlag bool   `json:"disableFlag"`
}

// RecordFailoverObj Failover info
type RecordFailoverObj struct {
	FailoverType    int                    `json:"failoverType"`
	Values          []RecordFailoverValues `json:"values"`
	SortOrder       int                    `json:"sortOrder,omitempty"`
	Failovertypestr string                 `json:"failoverTypeStr,omitempty"`
	FailedFlag      bool                   `json:"failedFlag,omitempty"`
	MarkedActive    bool                   `json:"markedActive,omitempty"`
	Disabled        bool                   `json:"disabled,omitempty"`
}

// RoundRobinFailoverObjValues RR Failover values
type RoundRobinFailoverObj struct {
	CheckID      int    `json:"checkId"`
	Value        string `json:"value"`
	DisableFlag  bool   `json:"disableFlag"`
	SortOrder    int    `json:"sortOrder,omitempty"`
	FailedFlag   bool   `json:"failedFlag,omitempty"`
	MarkedActive bool   `json:"markedActive,omitempty"`
}

// ConstellixRecord domain record
type ConstellixRecord struct {
	ID                 int                     `json:"id"`
	Name               string                  `json:"name,omitempty"`
	TTL                int                     `json:"ttl,omitempty"`
	Geolocation        *GeolocationObj         `json:"geolocation,omitempty"`
	RecordOption       string                  `json:"recordOption,omitempty"`
	NoAnswer           bool                    `json:"noAnswer,omitempty"`
	Note               string                  `json:"note,omitempty"`
	GtdRegion          int                     `json:"gtdRegion,omitempty"`
	Type               string                  `json:"type,omitempty"`
	ParentID           int                     `json:"parentId,omitempty"`
	Parent             string                  `json:"parent,omitempty"`
	Source             string                  `json:"source,omitempty"`
	ContactIDs         []int                   `json:"contactIds,omitempty"`
	RoundRobin         []RoundRobinObj         `json:"roundRobin"`
	RecordFailover     *RecordFailoverObj      `json:"recordFailover,omitempty"`
	Pools              []int                   `json:"pools,omitempty"`
	RoundRobinFailover []RoundRobinFailoverObj `json:"roundRobinFailover,omitempty"`
	ModifiedTs         int                     `json:"modifiedTs,omitempty"`
	ModifiedTsDate     time.Time               `json:"modifiedTsDate,omitempty"`
	Createdts          time.Time               `json:"createdTs,omitempty"`
	RecordType         string                  `json:"recordType,omitempty"`
	Disabled           bool                    `json:"disabled"`
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

// GetDomainID get domain id by name
func (client *Client) GetDomainID(name string) (int, error) {
	var domains []ConstellixDomain
	body, err := client.APIRequest("v1/domains/search", "exact="+name, "GET")
	if err != nil {
		return 0, err
	}
	json.Unmarshal(body, &domains)
	return int(domains[0].ID), nil
}

// GetDomainByName Get a single domain, by name
func (client *Client) GetDomainByName(name string) (ConstellixDomain, error) {
	var domain ConstellixDomain
	id, err := client.GetDomainID(name)
	if err != nil {
		return ConstellixDomain{}, err
	}
	body, err := client.APIRequest("v1/domains/"+strconv.Itoa(id), "", "GET")
	if err != nil {
		return ConstellixDomain{}, err
	}
	json.Unmarshal(body, &domain)
	return domain, nil
}

// ListDomains get a bare list of all domain names
func (client *Client) ListDomains() ([]string, error) {
	var domainList []string
	var err error
	domainObjects, err := client.GetAllDomains()

	for _, domain := range domainObjects {
		domainList = append(domainList, domain.Name)
	}
	return domainList, err
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
func (client *Client) GetRecordsByDomainName(name string) ([]ConstellixRecord, error) {
	id, err := client.GetDomainID(name)
	if err != nil {
		return []ConstellixRecord{}, err
	}
	domainRecords, err := client.GetDomainRecords(id)
	if err != nil {
		return []ConstellixRecord{}, err
	}
	return domainRecords, nil
}

// GetDomainRecords get all records for one domain by domain ID
func (client *Client) GetDomainRecords(domainid int) ([]ConstellixRecord, error) {
	var records []ConstellixRecord
	body, err := client.APIRequest("v1/domains/"+strconv.Itoa(domainid)+"/records", "", "GET")
	//TODO: go through paging
	//TODO: check error
	if err != nil {
		return []ConstellixRecord{}, err
	}
	err = json.Unmarshal(body, &records)
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
		return nil, errors.New("Unknown request type: " + reqtype)
	}

	req.Header.Add(authHeaderName, client.Token)
	req.Header.Add("User-Agent", client.UserAgent)
	req.Header.Add("Content-type", "application/json")
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, err
}
