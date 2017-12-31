package main

import (
  "strings"
)

// getSubDomain takes a raw input and a domain and returns the subdomain portion.
func getSubDomain(r string, d string) string {
  subd := strings.Replace(r, d, "", 1)

  // If there was a subdomain, remove the trailing dot.
  if strings.HasSuffix(subd, ".") {
    subd = subd[:len(subd)-1]
  }

  return subd
}

// deDupeDomains replaces wildcards in a domainList.
func (dl *domainList) deDupeDomains() {

  seen := map[string]bool{}
  result := []string{}

  for _, domain := range dl.rawDomains {
    // Replace wildcards with a generic subdomain.
    if strings.HasPrefix(domain, "*.") {
      domain = strings.Replace(domain, "*.", "www.", 1)
    }

    if seen[domain] != true {
      seen[domain] = true
      result = append(result, domain)
    }
  }
  // Overwrite the receivers domains list.
  dl.rawDomains = result
}

