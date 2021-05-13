# gostellix
Simple go library for Constellix API

Example:
```golang
package main

import (
	"encoding/json"
	"fmt"
	"gostellix/gostellix"
)

var apikey, secretkey string = "***-***-***-***-***", "***-***-***-***-***"

func checkErr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func printStruct(jsonStruct interface{}) {
	json_var, err := json.MarshalIndent(jsonStruct, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(json_var))
}

func main() {
	gstell := gostellix.New(apikey, secretkey)

	var domains []gostellix.ConstellixDomain
	domains, _ = gstell.GetAllDomains()
	for _, domain := range domains {
		// printStruct(domain)
		fmt.Println(domain)
	}

	domainName := "example.com"

	id, err := gstell.GetDomainID(domainName)
	checkErr(err)
	fmt.Printf("ID: %v",id)

	domain, err := gstell.GetDomainByName(domainName)
	checkErr(err)
	printStruct(domain)

	records, err := gstell.GetRecordsByDomainName(domainName)
	checkErr(err)
	printStruct(records)
	for _, item := range records{
		fmt.Printf("type: %v, option: %v \n", item.RecordType, item.RecordOption)
	}
	fmt.Println(len(records))
}
}```
