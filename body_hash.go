package dkim

import (
	"hash"
)

// simpleBodyHash is used to generate the body hash using simple canonicalization.
// simpleBodyHash implements io.Writer. Write chunks of body content to it,
// write the whole body at once, or copy the body from a reader using io.Copy.
type simpleBodyHash struct {
	h     hash.Hash
	crlfs []byte
}

// newSimpleBodyHash creates a new simpleBodyHash.
func newSimpleBodyHash(hash hash.Hash) *simpleBodyHash {
	return &simpleBodyHash{
		h:     hash,
		crlfs: make([]byte, 0, 8), // small initial empty buffer
	}
}

// Write (chunk of) raw body using "simple" canonicalization.
// It ignores all empty lines at the end of the last Write.
// Close() should be called to add the final single CRLF.
func (bh *simpleBodyHash) Write(p []byte) (n int, err error) {
	l := len(p)
	if l == 0 {
		return
	}
	// find trailing CR/LFs in this chunk
	i := l
	for {
		c := p[i-1]
		if c == '\r' || c == '\n' {
			i--
			if i == 0 {
				break
			}
		} else {
			break
		}
	}
	// write trailing CR/LFs from last chunk if this chunk has non-empty lines
	if len(bh.crlfs) != 0 && i > 0 {
		nw, ew := bh.h.Write(bh.crlfs)
		bh.crlfs = bh.crlfs[0:0] // clear buffer
		n += nw
		if ew != nil {
			return n, ew
		}
	}
	// write this chunk up to trailing CR/LFs
	nw, ew := bh.h.Write(p[0:i])
	n += nw
	if ew != nil {
		return n, ew
	}
	// save trailing CR/LFs for next write
	if i != l {
		bh.crlfs = append(bh.crlfs, p[i:l]...)
	}
	return
}

// Sum calculates the hash.
func (bh *simpleBodyHash) Sum() []byte {
	bh.h.Write([]byte("\r\n")) // write final CRLF
	return bh.h.Sum(nil)
}
