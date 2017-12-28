package main

import (
  "bytes"
  "fmt"
  "log"
  "os"
  //"regexp"
  "strings"

  "golang.org/x/net/idna"
  "github.com/CaliDog/certstream-go" // certstream api library
  "github.com/forease/gotld" // determine a tld using the public suffix list
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
    "ḣ": "h", "ã": "a", "ì": "i","ú":"u","ð", "o", "æ", "ae",
  }
)

// unicodeToASCII replaces unicode characters with their similar ASCII versions.
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

func main() {

  logger.SetOutput(os.Stderr)

  //re := regexp.MustCompile(regex)

  stream, errStream := certstream.CertStreamEventStream(true)
  for {
    select {
      case jq := <-stream:
        // Extract the domains from jq["data"]["leaf_cert"]["all_domains"].
        domains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
        if err != nil{
          logger.Fatalf("Error extracting domains from certstream: %s", err)
        }

        // Iterate over the list of domains.
        for _, d := range domains {

          // Replace wildcard cert with a generic subdomain.
          if strings.HasPrefix(d, "*.") {
            d = strings.Replace(d, "*.", "www.", 1)
          }

          // Use public suffix list data to extract the domain and TLD.
          tld, domain, err := gotld.GetTld(d)
          if err != nil{
            logger.Printf("Error extracting tld and domain from domain: %s", d)
          }

          // For PunyCode domains, get a Unicode representation.
          if strings.HasPrefix(domain, "xn--") {
            unicodeDomain, err := idna.Punycode.ToUnicode(domain)
            asciiUnicodeDomain := unicodeToASCII(unicodeDomain)
            if err != nil{
              logger.Print("Error converting punycode to unicode")
            }

            fmt.Printf("Uni:\t%s\nASC:\t%s\n", unicodeDomain, asciiUnicodeDomain)

          }

          subdomain := strings.Replace(d, domain, "", 1)

          // If there was a subdomain, remove the trailing dot.
          if strings.HasSuffix(subdomain, ".") {
            subdomain = subdomain[:len(subdomain)-1]
          }

          fmt.Printf("Inp:\t%s\nDom:\t%s\nSub:\t%s\nTLD:\t%s\n*****\n", d, domain, subdomain, tld.Tld)
        }
      
      case err := <-errStream:
        logger.Print(err)
        fmt.Print(&buf)
    }
  }
}