/*
 * phising.go implements the phishing detection logic.
 */

package main

import (
	"fmt"
)

// isPhishing checks if a domainList contains phishing domains.
func (dl *domainList) isPhishing() {

	var suspicious = false

	// Free certificates are more likely to be used for phishing
	for _, subject := range dl.subjects {
		if freeCaRe.MatchString(subject) {
			suspicious = true
		}
	}

	for _, dp := range dl.domains {
		// If we didnt extract a domain or subdomain, then continue.
		if isEmpty(dp.domain) || isEmpty(dp.subdomain) {
			continue
		}

		// Extract the keywords from the dp maps.
		keywords := getKeywords(dp.raw, phishingRe)
		domainKeywords := getKeywords(dp.domain, phishingRe)
		subDomainKeywords := getKeywords(dp.subdomain, phishingRe)

		// This is never used in the nodejs version either. Seems to be useful
		// though since many phishing subdomains are long strings of hyphenated
		// words.
		// dashes := len(getKeywords(dp.raw, dashes))
		// dots := len(getKeywords(dp.raw, dots))

		if dp.hasPunycode {
			punycodeKeywords := phishingRe.FindAllString(dp.raw["ascii"], -1)

			if len(keywords) > 0 && len(punycodeKeywords) > 0 {
				fmt.Printf("%s[!] Punycode %s%s%s = %s (%s, %s)\n", RL, RED,
					dp.raw["original"], RES, dp.raw["ascii"],
					keywords, punycodeKeywords)
			}

			return
		}

		if len(tlds) > 0 {
			if dp.containsTld(tlds) {
				// Only return results when we see a tld in our list.
				if suspicious {
					if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
						fmt.Printf("%s[!] Suspicious %s%s%s\n", RL, RED, dp.raw["original"], RES)
						return
					}

					if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
						fmt.Printf("%s[!] Likely %s%s%s\n", RL, YEL, dp.raw["original"], RES)
						return
					}
				} else {
					if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
						fmt.Printf("%s[!] Likely %s%s%s\n", RL, YEL, dp.raw["original"], RES)
						return
					}

					if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
						fmt.Printf("%s[!] Potential %s%s%s\n", RL, WHI, dp.raw["original"], RES)
						return
					}
				}
			}
		} else {
			// Return results for all TLDs
			if suspicious {
				if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
					fmt.Printf("%s[!] Suspicious %s%s%s\n", RL, RED, dp.raw["original"], RES)
					return
				}

				if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
					fmt.Printf("%s[!] Likely %s%s%s\n", RL, YEL, dp.raw["original"], RES)
					return
				}
			} else {
				if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
					fmt.Printf("%s[!] Likely %s%s%s\n", RL, YEL, dp.raw["original"], RES)
					return
				}

				if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
					fmt.Printf("%s[!] Potential %s%s%s\n", RL, WHI, dp.raw["original"], RES)
					return
				}
			}
		}
	}
}
