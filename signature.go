// Package dkim is used for signing emails with DKIM.
package dkim

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"net/mail"
	"strings"
)

// Hash is the algorithm used for hashing. SHA256 is recommended by the RFC.
// Change this to crypto.SHA1 if you need to.
var Hash = crypto.SHA256

// SignHeaderFields lists the header names to sign. These headers are
// recommended in RFC 6376 section 5.4.1. The list can be changed at will.
// This implementation signs each instance, if the header field occurs more than once.
// The basic rule for choosing fields to include is to select those fields that
// constitute the "core" of the message content.
// Note that "From" is required and "DKIM-Signature" is implicitly signed.
var SignHeaderFields = []string{
	"From",
	"Reply-to",
	"Subject",
	"Date",
	"To",
	"Cc",
	"Resent-Date",
	"Resent-From",
	"Resent-Sender",
	"Resent-To",
	"Resent-Cc",
	"In-Reply-To",
	"References",
	"List-Id",
	"List-Help",
	"List-Unsubscribe",
	"List-Subscribe",
	"List-Post",
	"List-Owner",
	"List-Archive",
}

// Signature represents DKIM-Signature header field.
type Signature struct {
	domain   *Domain
	bodyHash *simpleBodyHash
	bh       string // base-64 encoded body hash
	fields   string // signed header fields
	data     string
}

// NewSignature creates a signature signed by the specified domain.
func NewSignature(domain *Domain) *Signature {
	return &Signature{
		domain:   domain,
		bodyHash: newSimpleBodyHash(Hash.New()),
	}
}

// BodyWriter returns a writer that should receive the message body for
// calculating the body hash in the "bh=" tag. The body should be written before
// SignHeader is called. It is assumed that the body has proper CRLF line ends.
func (sig *Signature) BodyWriter() io.Writer {
	return sig.bodyHash
}

// SignHeader adds the header fields in SignHeaderFields from the mail.Header to
// the signature. The header hash is signed with the domain private key and used
// for the "b=" tag.
func (sig *Signature) SignHeader(header mail.Header) (err error) {

	sig.bh = base64.StdEncoding.EncodeToString(sig.bodyHash.Sum())

	hh := newRelaxedHeaderHash(Hash.New())
	for name, values := range header {
		if inSignHeaderFields(name) {
			// Signers choosing to sign an existing header field that occurs more
			// than once in the message (such as Received) MUST sign the physically
			// last instance of that header field in the header block.  Signers
			// wishing to sign multiple instances of such a header field MUST
			// include the header field name multiple times in the "h=" tag of the
			// DKIM-Signature header field and MUST sign such header fields in order
			// from the bottom of the header field block to the top.
			for i := len(values) - 1; i >= 0; i-- {
				hh.AddHeader(name, values[i])
			}
		}
	}
	// add canonicalized dkim-signature to hash
	sig.fields = strings.Join(hh.HeaderList(), ":")
	sum := hh.Sum(sig.value())

	// hash is signed using RSA algorithm defined in PKCS#1 version 1.5
	signed, err := sig.domain.sign(sum)
	if err != nil {
		return
	}
	sig.data = base64.StdEncoding.EncodeToString(signed)
	return
}

func inSignHeaderFields(name string) bool {
	for _, s := range SignHeaderFields {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

// value of signature field to be added to header hash
// with relaxed canonicalization and empty b= tag
func (sig *Signature) value() string {
	return fmt.Sprintf("v=1; a=%s; c=relaxed/simple; s=%s; d=%s; h=%s; bh=%s; b=",
		algName(Hash),
		sig.domain.Selector,
		sig.domain.Name,
		sig.fields,
		sig.bh)
}

// WriteTo writes the complete DKIM-Signature with trailing CRLF to the writer.
func (sig *Signature) WriteTo(w io.Writer) (n int64, err error) {
	// fold data tag at column 72
	var data []byte
	left := sig.data
	if len(left) > 65 {
		data = append(data, left[0:65]...)
		data = append(data, "\r\n\t "...)
		left = left[65:]
		for len(left) > 66 {
			data = append(data, left[0:66]...)
			data = append(data, "\r\n\t "...)
			left = left[66:]
		}
	}
	data = append(data, left...)
	// order of tags must match with signature body as added to header hash
	l, err := fmt.Fprintf(w, "DKIM-Signature: "+
		"v=1; a=%s; c=relaxed/simple; s=%s; d=%s;\r\n\th=%s;\r\n\tbh=%s;\r\n\tb=%s\r\n",
		algName(Hash),
		sig.domain.Selector,
		sig.domain.Name,
		sig.fields,
		sig.bh,
		data)
	return int64(l), err
}

func algName(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA1:
		return "rsa-sha1"
	case crypto.SHA256:
		return "rsa-sha256"
	default:
		return "?"
	}
}
