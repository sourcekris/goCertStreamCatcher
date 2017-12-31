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
  // tlds = []string{".io",".gq",".ml",".cf",".tk",".xyz",".pw",".cc",".club",".work",".top",".support",".bank",".info",".study",".party",".click",".country",".stream",".gdn",".mom",".xin",".kim",".men", ".loan", ".download", ".racing", ".online", ".center", ".ren", ".gb", ".win", ".review", ".vip", ".party", ".tech", ".science", ".business", ".com"}
  phishingRe = regexp.MustCompile("(?:yobit|bitfinex|etherdelta|iqoption|localbitcoins|etoto|ethereum|wallet|mymonero|visa|blockchain|bitflyer|coinbase|hitbtc|lakebtc|bitfinex|bitconnect|coinsbank|moneypaypal|moneygram|westernunion|bankofamerica|wellsfargo|itau|bradesco|nubank|paypal|bittrex|blockchain|netflix|gmail|yahoo|google|apple|amazon)")
  whiteList = regexp.MustCompile("(?:sni\\d+\\.cloudflaressl\\.com)")
  freeCaRe = regexp.MustCompile("(?:Let\\'s\\ Encrypt|StartSSL|Free\\ SSL|CACert\\ free\\ certificate|Cloudflare)")
)

/* 
func countDashes(s string) int {

}

//
func countSubdomains(s string) int {

}*/

// isPhishing checks if a domainList contains phishing domains. 
func (dl *domainList) isPhishing() {
  // Is the issuer an issuer of free SSL certificates?
  for _, ca := range dl.subjects {
    if freeCaRe.MatchString(ca) {
      dl.suspicious = append(dl.suspicious, 30)
    }
  }
  
  // Does the domain contain phishing keywords?
  // dl.domains is a list of domainParts
  for _, dp := range dl.domains {
    // dp.raw is a map[string]string containing original and transformed domains.
    for k, v := range dp.raw {
      // If there's one match to the whitelist, remove all tags and continue.
      if whiteList.MatchString(v) {
        dl.phishing = dl.phishing[:0]
        dl.suspicious = dl.suspicious[:0]
        continue
      }

      if phishingRe.MatchString(v) {
        dl.phishing = append(dl.phishing, 100) // 100 points for a match on any value 

        // If the ascii version of the domain matches the regex but the original doesnt, then
        // this is likely a "homograph attack"
        if k == "ascii" && !phishingRe.MatchString(dp.raw["original"]) {
          dl.phishing = append(dl.phishing,20) // Additional 20 points for the homograph attack
          dl.suspicious = append(dl.suspicious, 20) // This is also quite suspicious.
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

        phishing := sumArray(dl.phishing)
        suspicious := sumArray(dl.suspicious)

        if phishing > 0 || suspicious > 30 {
          fmt.Printf("dl.rawDomains = %s\ndl.phishing = %d, dl.suspicious = %d\n", dl.rawDomains, sumArray(dl.phishing), sumArray(dl.suspicious))  
        }
              
      case err := <-errStream:
        logger.Print(err)
        fmt.Print(&buf)
    }
  }
}