// Package signature signs and unsigns cookies. It can also unsign cookies
// created by node-cookie-signature if the same 'secret' is used,
// allowing interoperability with node.js sessions
package signature

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"strings"
)

// Create an HMAC signature that is identical to one produced by node-cookie-signature
func computeHmac256(message string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))
	digest := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return strings.TrimRight(digest, "=")
}

// Appends a '.' and then a signature to 'val', calculated using the provided secret
func Sign(val string, secret string) string {
	return val + "." + computeHmac256(val, secret)
}

// Extracts the value (the part of the string before the '.') from val. 'Valid' is true
// if the signature is valid, otherwise false.
func Unsign(val string, secret string) (str string, valid bool) {
	// cookie must begin with "s:"
	/*
		if !strings.HasPrefix(val, "s:") {
			valid = false
			return
		}
		val = val[2:]
	*/
	log.Printf("unsign val=%s", val)
	str = strings.Split(val, ".")[0]
	log.Printf("unsign str=%s", str)
	signed := Sign(str, secret)
	log.Printf("unsign signed=%s", signed)

	/*
	   In certain cases, information can be leaked by using a timing attack. It takes advantage of the == operator only comparing until it finds a difference in the two strings. To prevent it,
	       hash both hashed strings first - this doesn't stop the timing difference, but it makes the information useless.
	*/
	valid = sha1.Sum([]byte(signed)) == sha1.Sum([]byte(val))
	return
}
