package dkim

import (
	"hash"
	"strings"
)

// relaxedHeaderHash is used to generate the header hash using relaxed canonicalization.
type relaxedHeaderHash struct {
	h hash.Hash
	a []string
}

// newRelaxedHeaderHash creates a relaxedHeaderHash using the specified hash implementation.
func newRelaxedHeaderHash(hash hash.Hash) *relaxedHeaderHash {
	return &relaxedHeaderHash{
		h: hash,
		a: make([]string, 0, 16),
	}
}

// AddHeader adds a header to the hash. The header name will be converted to
// lowercase. The header value must be unfolded and with leading and trailing
// whitespace trimmed. A CRLF will be added after the header.
func (hh *relaxedHeaderHash) AddHeader(name, value string) {
	hh.h.Write([]byte(strings.ToLower(name)))
	hh.h.Write([]byte(":"))
	hh.h.Write([]byte(value))
	hh.h.Write([]byte("\r\n"))
	hh.a = append(hh.a, name)
}

// HeaderList returns the header names added to the hash and should
// be used to populate the h= parameter in the signature.
func (hh *relaxedHeaderHash) HeaderList() []string {
	return hh.a
}

// Sum adds the signature value as final header to the hash and returns the sum.
// The signature value must be unfolded with all tags populated except "b=".
func (hh *relaxedHeaderHash) Sum(signature string) []byte {
	hh.h.Write([]byte("dkim-signature:"))
	hh.h.Write([]byte(signature))
	return hh.h.Sum(nil)
}
