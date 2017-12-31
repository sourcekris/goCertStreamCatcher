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
  regex = regexp.MustCompile("(?:yobit|bitfinex|etherdelta|iqoption|localbitcoins|etoto|ethereum|wallet|mymonero|visa|blockchain|bitflyer|coinbase|hitbtc|lakebtc|bitfinex|bitconnect|coinsbank|moneypaypal|moneygram|westernunion|bankofamerica|wellsfargo|itau|bradesco|nubank|paypal|bittrex|blockchain|netflix|gmail|yahoo|google|apple|amazon)")
)

// isPhishing checks if a domainList contains phishing domains. 
func (dl *domainList) isPhishing() {

  // dl.domains is a list of domainParts
  for _, dp := range dl.domains {
    // dp.raw is a map[string]string containing original and transformed domains.
    for k, v := range dp.raw {
      if regex.MatchString(v) {
        dl.phishing = append(dl.phishing, 100) // 100 points for a match on any value 

        // If the ascii version of the domain matches the regex but the original doesnt, then
        // this is likely a "homograph attack"
        if k == "ascii" && !regex.MatchString(dp.raw["original"]) {
          dl.phishing = append(dl.phishing,20) // Additional 20 points for the homograph attack
          dl.suspicious = append(dl.suspicious, 20) // This is also quite suspicious.
        }
      }
    }  
  }
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
        
        fmt.Printf("subject.aggregated: %s\n", dl.subjectAggregated)
        dl.deDupeDomains()
        dl.extractDomainParts()

        for _, dp := range dl.domains {
          fmt.Printf("dp.raw = %s\ndp.domain = %s\ndp.subdomain = %s\ndp.tld = %s\n", 
                      dp.raw, dp.domain, dp.subdomain, dp.tld)
        }
      
      case err := <-errStream:
        logger.Print(err)
        fmt.Print(&buf)
    }
  }
}