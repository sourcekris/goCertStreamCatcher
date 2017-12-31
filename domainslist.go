package main

import (
  "errors"
  "github.com/jmoiron/jsonq"
)

type domainList struct {
  subjects []string // 
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

  chain, err := jq.ArrayOfObjects("data", "chain")
  if err != nil{
    return nil, errors.New("Error extracting certificate chain from certstream: " + err.Error())
  }

  var subjects []string

  // Build a list of the certificate chain's subject.aggregated fields.  
  for _, c := range chain {
    cert := jsonq.NewQuery(c)
    s, err := cert.String("subject", "aggregated")
    if err != nil{
      return nil, errors.New("Error extracting certificate chain from certstream: " + err.Error())
    }

    subjects = append(subjects, s)
  }

  return &domainList{
    subjects: subjects,
    rawDomains: d,
  }, nil
}