# dkim

Library for signing emails with DKIM.

The purpose of this library is to create a solution for DKIM signing in Go that is fast, simple, and suitable for bulk mail applications.

To create the body hash, the body can be written in chunks, written all at once, or copied from an io.Reader using io.Copy. There is no need to present the complete message or body as a byte slice in memory. At this moment only "simple" body canonicalization is supported, which is efficient and secure. The only prerequisite is that body lines have proper CRLF line terminators.

The create the header hash, a standard mail.Header is used for input. This saves parsing when a mail.Header is already available. At this moment only "relaxed" header canonicalization is supported, which is reliable and most common. Part of the canonicalization is done by mail.ReadMessage or textproto.Reader.ReadMIMEHeader when a mail.Header is created.

Because mail.Header is implemented with a map, the order of headers in the "h=" tag is non-deterministic. Repeated headers are represented as array values in mail.Header and are signed bottom most first. This should be fine, since validators will follow the ordering in the "h=" tag and repeated headers are processed in the same order as they are signed.

The hashing algorithm is considered a global policy and can be changed from SHA256 to SHA1. The headers that are included in the signature can also be changed by modifying a global parameter. For headers that are repeated all instances will be signed.

## Using

First create a signing domain from a private key in memory or read it from disk:

	domain, err := dkim.ReadDomain("emailfabric.com", "test", "test/test.rsa")
	if err != nil {
		return
	}
	
You need a mail.Header for the email header and a io.Reader for the email body. You can use mail.ReadMessage to create these:

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return
	}

Creating the signature goes as follows:

	sig := dkim.NewSignature(domain)
	
	// step 1
	_, err = io.Copy(sig.BodyWriter(), msg.Body)
	if err != nil {
		return
	}

	// step 2
	err = sig.SignHeader(msg.Header)
	if err != nil {
		return
	}
	
The signature must be prepended to the email header. Just write it before writing the email message:

	_, err = sig.WriteTo(writer)
	if err != nil {
		return
	}

Complete API documentation can be found at [GoDoc](http://godoc.org/github.com/emailfabric/dkim).
