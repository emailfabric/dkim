package dkim

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

// testHash implements hash.Hash
type testHash struct {
	*bytes.Buffer
}

func newTestHash() *testHash {
	return &testHash{&bytes.Buffer{}}
}

func (h *testHash) Sum([]byte) []byte { return h.Bytes() }

func (h *testHash) Size() int { return h.Len() }

func (h *testHash) BlockSize() int { return 0 }

func TestSimpleBodyCanonWrite(t *testing.T) {

	th := newTestHash()
	bh := newSimpleBodyHash(th)
	// sample from RFC 6376 section 3.4 example 3
	bh.Write([]byte(" C \r\n"))
	bh.Write([]byte("D \t E\r\n"))
	bh.Write([]byte("\r\n"))
	bh.Write([]byte("\r\n"))
	if string(bh.Sum()) != " C \r\nD \t E\r\n" {
		t.Errorf("unexpected output: %q\n", th.String())
	}
}

func TestSimpleBodyCanonCopy(t *testing.T) {
	// test with empty lines crossing buffer boundary
	doTestSimpleBodyCanonCopy(t, 10)
	doTestSimpleBodyCanonCopy(t, 11)
	doTestSimpleBodyCanonCopy(t, 12)
	doTestSimpleBodyCanonCopy(t, 13)
}

func doTestSimpleBodyCanonCopy(t *testing.T, copyBufferSize int) {
	// sample from RFC 6376 section 3.4 example 3
	body := strings.NewReader(" C \r\nD \t E\r\n\r\n\r\n")

	th := newTestHash()
	bh := newSimpleBodyHash(th)
	io.CopyBuffer(bh, body, make([]byte, copyBufferSize))
	if string(bh.Sum()) != " C \r\nD \t E\r\n" {
		t.Errorf("unexpected output: %q\n", th.String())
	}
}

func TestEmptyBodySHA1Hash(t *testing.T) {
	// example from RFC 6376 section 3.4.3.
	bh := base64.StdEncoding.EncodeToString(newSimpleBodyHash(crypto.SHA1.New()).Sum())
	if bh != "uoq1oCgLlTqpdDX/iUbLy7J1Wic=" {
		t.Errorf("Unexpected body SHA-1 hash: %s", bh)
	}
}

func TestEmptyBodySHA256Hash(t *testing.T) {
	// example from RFC 6376 section 3.4.3.
	bh := base64.StdEncoding.EncodeToString(newSimpleBodyHash(crypto.SHA256.New()).Sum())
	if bh != "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=" {
		t.Errorf("Unexpected body SHA-256 hash: %s", bh)
	}
}
