# goCertStreamCatcher
Catching phishing by observing [certificate transparency logs](https://www.certificate-transparency.org/known-logs). This tool is based on regex with effective standards for detecting phishing sites in real time using [certstream](https://github.com/CaliDog/certstream-go) and can also detect [punycode (IDNA)](https://en.wikipedia.org/wiki/Punycode) attacks such as https://www.ṁyetḣerwallet.com.

This is a go port of the [nodejs version](https://github.com/6IX7ine/certstreamcatcher) originally by [@6IX7ine](https://twitter.com/6IX7ine).


### Building

```
$ go get github.com/sourcekris/goCertStreamCatcher
$ cd $GOPATH/src/github.com/sourcekris/goCertStreamCatcher
$ go build

```
    
### Usage
Right now it builds a standalone binary `goCertStreamCatcher` so simply `go build` it and run `./goCertStreamCatcher`

### Todo
 * Verify the punycode logic is as expected.
 * Probably influence the logic more if the subdomain has a lot of dashes/periods
 * Add additional analysis logic to detect other suspicious domain 
 * Headless browse the suspicious sites and grab screenshots?