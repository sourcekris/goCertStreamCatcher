package main

import (
  "errors"
  "github.com/jmoiron/jsonq"
)

type domainList struct {
  rawDomains []string // domains from the certificate
  phishing []int   // phishing indicators
  suspicious []int // suspicious indicators
  domains []domainParts
}

// newDomainList constructs a new domainList from a JsonQuery object.
func newDomainList(jq jsonq.JsonQuery) (*domainList, error) {
  // Extract the domains from jq["data"]["leaf_cert"]["all_domains"].
  d, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
  if err != nil{
    return nil, errors.New("Error extracting domains from certstream: " + err.Error())
  }

  return &domainList{
    rawDomains: d,
  }, nil
}