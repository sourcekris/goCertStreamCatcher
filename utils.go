package main

import (
	"regexp"
	"strings"
)

// isEmpty is a map helper function to see if we have no values.
func isEmpty(m map[string]string) bool {
	for _, v := range m {
		if v == "" {
			return true
		}
	}
	return false
}

// getKeywords returns an array of keywords that match values in a map[string]string.
func getKeywords(m map[string]string, r *regexp.Regexp) []string {
	var keywords []string
	for _, v := range m {
		keywords = r.FindAllString(v, -1)
	}
	return keywords
}

// hasKeywordsPrefix checks if any of the b keywords start with any of the a keywords.
func hasKeywordsPrefix(a, b []string) bool {
	for _, k := range a {
		for _, t := range b {
			if strings.HasPrefix(t, k) {
				return true
			}
		}
	}
	return false
}

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
