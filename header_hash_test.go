package dkim

import (
	"net/mail"
	"strings"
	"testing"
)

func TestRelaxedHeaderCanon(t *testing.T) {
	// RFC 6376 section 3.4 example 3
	msg, err := mail.ReadMessage(strings.NewReader("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n"))
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	// note that part of the canonicalization is done when parsing header

	th := newTestHash()
	hh := newRelaxedHeaderHash(th)
	hh.AddHeader("A", msg.Header["A"][0])
	hh.AddHeader("B", msg.Header["B"][0])
	if th.String() != "a:X\r\nb:Y Z\r\n" {
		t.Errorf("unexpected output: %q\n", th.String())
	}
}
