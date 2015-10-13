// Black box testing for signature package
package signature_test

import (
	"testing"

	"github.com/mattbarton/go-cookie-signature/signature"
)

func TestSign(t *testing.T) {
	val := signature.Sign("hello", "tobiiscool")
	if val != "hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI" {
		t.Error("Expected signed value, instead got ", val)
	}
	val2 := signature.Sign("hello", "wrongsecret")
	if val2 == "hello.DGDUkGlIkCzPz+C0B064FNgHdEjox7ch8tOBGslZ5QI" {
		t.Error("Expected different value due to different secret")
	}
}

func TestUnsign(t *testing.T) {
	const SECRET = "correctsecret"
	val := signature.Sign("hello", SECRET)
	if str, valid := signature.Unsign(val, SECRET); str != "hello" || !valid {
		t.Error("Expected valid str 'hello', instead got ", val, str, valid)
	}
	if _, valid := signature.Unsign(val, "wrongsecret"); valid {
		t.Fail()
	}
}
