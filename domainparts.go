package main

import (
  "errors"
  "strings"
  "github.com/sourcekris/gotld" // determine the TLD
)

type domainParts struct {
  raw map[string]string
  domain map[string]string
  subdomain map[string]string
  tld map[string]string
  hasPunycode bool
}

// newDomainParts deconstructs an input 'domain' into a subdomain, domain, and tld struct.
func newDomainParts(d string) (*domainParts, error) {
  // Use public suffix list data to extract the domain and TLD.
  tl, dom, err := gotld.GetTld(d)
  if err != nil{
    return nil, errors.New("Error extracting tld and domain from domain: " + d + err.Error())
  }

  dp := &domainParts{
    raw: map[string]string{"original":d},
    domain: map[string]string{"original":dom},
    subdomain: map[string]string{"original":getSubDomain(d, dom)},
    tld: map[string]string{"original":tl.Tld},
    hasPunycode: false,
  }

  // For a punycode domain, lets also get ascii items for domainParts
  if strings.Contains(d, "xn--") {
    dp.hasPunycode = true
    dp.raw["ascii"] = resolvePunycode(d)

    tl, dom, err = gotld.GetTld(dp.raw["ascii"])
    if err != nil{
      return dp, errors.New("Error extracting tld and domain from punycode domain: " + d + err.Error())
    }

    dp.domain["ascii"] = dom
    dp.subdomain["ascii"] = getSubDomain(dp.raw["ascii"], dp.domain["ascii"])
    dp.tld["ascii"] = tl.Tld
  }

  return dp, nil
}

// extractDomainParts takes a list of raw domains and builds a list of domainParts.
func (dl *domainList) extractDomainParts() {
  result := []domainParts{}

  // Iterate over the list of domains.
  for _, d := range dl.rawDomains {
    p, err := newDomainParts(d)
    if err != nil{
      logger.Print(err.Error())
    }
    result = append(result, *p)
  }

  dl.domains = result
}
