package main

import (
  "bytes"
  "errors"
  "fmt"
  "log"
  "os"
  //"regexp"
  "strings"

  "golang.org/x/net/idna"
  "github.com/jmoiron/jsonq"
  "github.com/CaliDog/certstream-go" // certstream api library
  "github.com/sourcekris/gotld" // determine the TLD
)

var (
  buf bytes.Buffer
  logger = log.New(&buf, "certstream: ", log.Lshortfile)
  tlds = []string{".io",".gq",".ml",".cf",".tk",".xyz",".pw",".cc",".club",".work",".top",".support",".bank",".info",".study",".party",".click",".country",".stream",".gdn",".mom",".xin",".kim",".men", ".loan", ".download", ".racing", ".online", ".center", ".ren", ".gb", ".win", ".review", ".vip", ".party", ".tech", ".science", ".business", ".com"}
  regex = "/(?:yobit|bitfinex|etherdelta|iqoption|localbitcoins|etoto|ethereum|wallet|mymonero|visa|blockchain|bitflyer|coinbase|hitbtc|lakebtc|bitfinex|bitconnect|coinsbank|moneypaypal|moneygram|westernunion|bankofamerica|wellsfargo|itau|bradesco|nubank|paypal|bittrex|blockchain|netflix|gmail|yahoo|google|apple|amazon)/gi"
  maps = map[string]string{
    "ṃ":"m","ł":"l","m":"m","š": "s", "ɡ":"g", "ũ":"u","e":"e",
    "í":"i","ċ": "c","ố":"o","ế": "e", "ệ":"e","ø":"o", "ę": "e", 
    "ö": "o", "ё": "e", "ń": "n", "ṁ": "m","ó": "o", "é": "e", 
    "đ": "d", "ė": "e", "á": "a", "ć": "c", "ŕ": "r", "ẹ": "e", 
    "ọ": "o", "þ": "p", "ñ": "n", "õ": "o", "ĺ": "l", "ü": "u", 
    "â": "a", "ı": "i", "ᴡ":"w", "α":"a","ρ":"p","ε":"e","ι":"l", 
    "å":"a", "п":"n","ъ":"b","ä":"a", "ç":"c","ê":"e", "ë":"e", 
    "ï": "i", "î":"i","ậ":"a","ḥ":"h","ý":"y", "ṫ":"t", "ẇ": "w", 
    "ḣ": "h", "ã": "a", "ì": "i","ú":"u","ð": "o", "æ": "ae",
  }
)

type domainList struct {
  domains []string // domains in each certificate
  phishing []int   // phishing indicators
  suspicious []int // suspicious indicators
}

type domainParts struct {
  raw string
  domain string
  subdomain string
  tld string
}

// newDomainList constructs a new domainList from a JsonQuery object.
func newDomainList(jq jsonq.JsonQuery) (*domainList, error) {
  // Extract the domains from jq["data"]["leaf_cert"]["all_domains"].
  d, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
  if err != nil{
    return nil, errors.New("Error extracting domains from certstream: " + err.Error())
  }

  return &domainList{
    domains: d,
  }, nil
}

// newDomainParts deconstructs an input 'domain' into a subdomain, domain, and tld struct.
func newDomainParts(d string) (*domainParts, error) {
  // Use public suffix list data to extract the domain and TLD.
  tl, dom, err := gotld.GetTld(d)
  if err != nil{
    return nil, errors.New("Error extracting tld and domain from domain: " + d + err.Error())
  }

  subd := strings.Replace(d, dom, "", 1)

  // If there was a subdomain, remove the trailing dot.
  if strings.HasSuffix(subd, ".") {
    subd = subd[:len(subd)-1]
  }

  return &domainParts{
    raw: d,
    domain: dom,
    subdomain: subd,
    tld: tl.Tld,
  }, nil
}

// unicodeToASCII replaces unicode characters with similar ASCII versions.
func unicodeToASCII(domain string) string {
  var str string

  for _, c := range domain {
    if val, ok := maps[string(c)]; ok {
      str = str + val
    } else {
      str = str + string(c)
    }
  }
  return string(str)
}

// deDupeDomains replaces wildcards in a domainList.
func (dl *domainList) deDupeDomains() {

  seen := map[string]bool{}
  result := []string{}

  for _, domain := range dl.domains {
    // Replace wildcard cert with a generic subdomain.
    if strings.HasPrefix(domain, "*.") {
      domain = strings.Replace(domain, "*.", "www.", 1)
    }

    if seen[domain] != true {
      seen[domain] = true
      result = append(result, domain)
    }
  }
  // Overwrite the receivers domains list.
  dl.domains = result
}

// resolvePunycode replaces IDN representations with an ASCII approximation in a domainList.
func (dl *domainList) resolvePunycode() {
  result := []string{}

  for _, domain := range dl.domains {
    // For PunyCode domains, get a Unicode representation.
    if strings.HasPrefix(domain, "xn--") {
      unicodeDomain, err := idna.Punycode.ToUnicode(domain)
      if err != nil{
        logger.Print("Error converting punycode to unicode")
      }
      fmt.Printf("XN:  %s\nUni: %s\n", domain, unicodeDomain)
      result = append(result, unicodeToASCII(unicodeDomain))
    } else {
      result = append(result, domain)
    }
  }

  // Overwrite the receivers domains list.
  dl.domains = result
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
        dl.resolvePunycode()

        // Iterate over the list of domains.
        for _, d := range dl.domains {
          p, err := newDomainParts(d)
          if err != nil{
            logger.Print(err.Error())
          }
          fmt.Printf("Inp:\t%s\nDom:\t%s\nSub:\t%s\nTLD:\t%s\n*****\n", 
                     p.raw, p.domain, p.subdomain, p.tld)
        }
      
      case err := <-errStream:
        logger.Print(err)
        fmt.Print(&buf)
    }
  }
}