package main

import (
  "bytes"
  "fmt"
  "log"
  "os"
  "regexp"

  "github.com/CaliDog/certstream-go" // certstream api library
)

var (
  buf bytes.Buffer
  logger = log.New(&buf, "certstream: ", log.Lshortfile)

  phishingRe = regexp.MustCompile("(?:yobit|bitfinex|etherdelta|iqoption|localbitcoins|etoto|ethereum|wallet|mymonero|visa|blockchain|bitflyer|coinbase|hitbtc|lakebtc|bitfinex|bitconnect|coinsbank|moneypaypal|moneygram|westernunion|bankofamerica|wellsfargo|itau|bradesco|nubank|paypal|bittrex|blockchain|netflix|gmail|yahoo|google|apple|amazon)")
  whiteList = regexp.MustCompile("(?:sni\\d+\\.cloudflaressl\\.com)")
  freeCaRe = regexp.MustCompile("(?:Let\\'s\\ Encrypt|StartSSL|Free\\ SSL|CACert\\ free\\ certificate|Cloudflare)")
  dashes = regexp.MustCompile("\\-")
  dots = regexp.MustCompile("\\.")

  tlds = []string{"io","gq","ml","cf","tk","xyz","pw","cc","club","work","top", "support",
                  "bank","info","study","party","click","country","stream", "gdn","mom",
                  "xin","kim","men", "loan", "download", "racing", "online", "center", 
                  "ren", "gb", "win", "review", "vip", "party", "tech", "science", 
                  "business", "com"}
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

    // dashes := len(getKeywords(dp.raw, dashes))
    // dots := len(getKeywords(dp.raw, dots))

    if dp.hasPunycode {
      punycodeKeywords := phishingRe.FindAllString(dp.raw["ascii"], -1)

      if len(keywords) > 0 && len(punycodeKeywords) > 0 {
        fmt.Printf("[!] Punycode %s = %s (%s, %s)\n", 
                   dp.raw["original"], dp.raw["ascii"], 
                   keywords, punycodeKeywords)
      }

      return
    }

    if len(tlds) > 0 {
      // Only return results when we see a tld in our list.
      if dp.containsTld(tlds) {
        if suspicious {
          if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
            fmt.Printf("[!] Suspicious %s\n", dp.raw["original"])
          }

          if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
            fmt.Printf("[!] Likely %s\n", dp.raw["original"])
          }
        } else {
          if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
            fmt.Printf("[!] Likely %s\n", dp.raw["original"])
          }

          if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
            fmt.Printf("[!] Potential %s\n", dp.raw["original"])
          }
        }
      }
    } else {
      if suspicious {
        if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
          fmt.Printf("[!] Suspicious %s\n", dp.raw["original"])
        }

        if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
          fmt.Printf("[!] Likely %s\n", dp.raw["original"])
        }
      } else {
        if hasKeywordsPrefix(keywords, subDomainKeywords) && len(subDomainKeywords) >= 1 {
          fmt.Printf("[!] Likely %s\n", dp.raw["original"])
        }

        if hasKeywordsPrefix(keywords, domainKeywords) && len(domainKeywords) >= 1 {
          fmt.Printf("[!] Potential %s\n", dp.raw["original"])
        }
      }
    }  
  }
}

func sumArray (a []int) int {
  var result int
  for _, v := range a {
    result = result + v
  }

  return result
}

func main() {

  logger.SetOutput(os.Stderr)

  //re := regexp.MustCompile(regex)

  stream, errStream := certstream.CertStreamEventStream(true)
  for {
    select {
      case jq := <-stream:
        dl, err := newDomainList(jq)
        if err != nil{
          logger.Printf(err.Error())
          continue
        }
        
        dl.deDupeDomains()
        dl.extractDomainParts()
        dl.isPhishing()
              
      case err := <-errStream:
        logger.Print(err)
        fmt.Print(&buf)
    }
  }
}