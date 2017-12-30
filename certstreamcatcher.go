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
    "м":"m", "л": "n",
  }
)

type domainParts struct {
  raw map[string]string
  domain map[string]string
  subdomain map[string]string
  tld map[string]string
  hasPunycode bool
}

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

// getSubDomain takes a raw input and a domain and returns the subdomain portion.
func getSubDomain(r string, d string) string {
  subd := strings.Replace(r, d, "", 1)

  // If there was a subdomain, remove the trailing dot.
  if strings.HasSuffix(subd, ".") {
    subd = subd[:len(subd)-1]
  }

  return subd
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

// resolvePunycode examines the IDN latin representation to find an ASCII approximation.
func resolvePunycode(d string) string {
  if !strings.Contains(d, "xn--") {
    return d
  }

  unicodeDomain, err := idna.Punycode.ToUnicode(d)
  if err != nil{
    logger.Print("Error converting punycode to unicode")
  }
  // fmt.Printf("XN:  %s\nUni: %s\n", d, unicodeDomain)

  // This is a safe noop when the domain failed to convert to Unicode.
  return unicodeToASCII(unicodeDomain)
}

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