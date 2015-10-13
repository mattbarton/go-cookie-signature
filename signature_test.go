// Black box testing for signature package
package signature_test

import (
	"testing"

	"github.com/mattbarton/node-cookie-signature/signature"
)

func TestSignCookie(t *testing.T) {
	val := signature.Sign("hello", "tobiiscool")
	if val != "hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI" {
		t.Fail()
	}
}
