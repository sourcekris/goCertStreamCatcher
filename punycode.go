/*
 * punycode.go - Punycode / Unicode functions.
 *
 * Author: Kris Hunt
 * License: See LICENSE
 */

package main

import (
  "strings"
  "golang.org/x/net/idna"
)

// TODO(sourcekris): This should be map[rune]rune.
var maps = map[string]string{
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

// unicodeToASCII replaces unicode characters with similar ASCII versions.
func unicodeToASCII(domain string) string {
  var str string

  // TODO(sourcekris): This should use runes instead of strings.
  for _, c := range domain {
    if val, ok := maps[string(c)]; ok {
      str = str + val
    } else {
      str = str + string(c)
    }
  }
  return string(str)
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

  // This is a safe noop when the domain failed to convert to Unicode.
  return unicodeToASCII(unicodeDomain)
}