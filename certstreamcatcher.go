package main

import (
  "bytes"
  "fmt"
  "log"
  "os"
  "regexp"

  "github.com/CaliDog/certstream-go" // certstream api library
)

const (
  RL = "\r\033[K"
  RED = "\033[31m\033[4m"
  YEL = "\033[33m\033[4m"
  WHI = "\033[37m\033[4m"
  RES = "\033[0m"
)

var (
  buf bytes.Buffer
  logger = log.New(&buf, "certstream: ", log.Lshortfile)

  phishingRe = regexp.MustCompile("(?:yobit|bitfinex|etherdelta|iqoption|localbitcoins|etoto|ethereum|wallet|mymonero|blockchain|bitflyer|coinbase|hitbtc|lakebtc|bitfinex|bitconnect|coinsbank|moneypaypal|moneygram|westernunion|bankofamerica|wellsfargo|itau|bradesco|nubank|paypal|bittrex|blockchain|netflix|gmail|yahoo|google|appleid|amazon)")
  freeCaRe = regexp.MustCompile("(?:Let\\'s\\ Encrypt|StartSSL|Free\\ SSL|CACert\\ free\\ certificate|Cloudflare)")
  dashes = regexp.MustCompile("\\-")
  dots = regexp.MustCompile("\\.")

  tlds = []string{"io","gq","ml","cf","tk","xyz","pw","cc","club","work","top", "support",
                  "bank","info","study","party","click","country","stream", "gdn","mom",
                  "xin","kim","men", "loan", "download", "racing", "online", "center", 
                  "ren", "gb", "win", "review", "vip", "party", "tech", "science", 
                  "business", "com"}
)

func main() {
  var count int

  logger.SetOutput(os.Stderr)

  stream, errStream := certstream.CertStreamEventStream(true)
  fmt.Printf("Connection established to certstream! Waiting for messages...\n")
  for {
    select {
      case jq := <-stream:
        count++
        fmt.Printf("%s%d Certs", RL, count)
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
    }
  }
}