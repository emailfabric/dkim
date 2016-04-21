package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
)

// Domain used for DKIM signing. Which domain to use for signing is left to the user.
// Common (and best) practice is to use the same domain as in the Sender: or From: header.
type Domain struct {
	Name       string
	Selector   string
	PrivateKey *rsa.PrivateKey
}

// ReadDomain creates a signing domain from name, selector and file with PEM encoded private key.
func ReadDomain(name, selector, keyfile string) (domain *Domain, err error) {
	pem, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return
	}
	key, err := ParsePrivateKey(pem)
	if err != nil {
		return
	}
	domain = &Domain{
		Name:       name,
		Selector:   selector,
		PrivateKey: key,
	}
	return
}

// Sign header hash using RSA algorithm defined in PKCS#1 version 1.5.
// Used for b= signature tag.
func (d *Domain) sign(hash []byte) (signed []byte, err error) {
	return rsa.SignPKCS1v15(rand.Reader, d.PrivateKey, Hash, hash)
}

// ParsePrivateKey returns the private key from a PEM formatted block.
func ParsePrivateKey(keyPEM []byte) (key *rsa.PrivateKey, err error) {
	der, _ := pem.Decode(keyPEM)
	return x509.ParsePKCS1PrivateKey(der.Bytes)
}

// GenerateKeyPair returns a new PEM encoded private key and base64 encoded
// public key.
func GenerateKeyPair(bits int) (keyPEM []byte, pubB64 string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKey := privateKey.Public()
	pub, err := x509.MarshalPKIXPublicKey(publicKey)
	pubB64 = base64.StdEncoding.EncodeToString([]byte(pub))
	return
}
