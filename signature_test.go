package dkim

import (
    "fmt"
	"io"
	"net/mail"
	"os"
	"testing"
)

/*
func TestSignatureWriteTo(t *testing.T) {
    signature := &Signature{
        domain: "example.com",
    	selector: "key1",
    	bodyHash: "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=",
    	fields: "Date:From:Subject",
    }

    // canonicalized field body
    body := signature.body()

    // folded header field
    buf := &bytes.Buffer{}
    signature.WriteTo(buf)
    field := buf.String()
    i := strings.IndexByte(field, ':')
    if i == -1 {
        t.Fatalf("malformed header line: %q", field)
    }

    // trim and unfold
    body2 := regexp.MustCompile("\\s+").ReplaceAllString(strings.TrimSpace(field[i+1:]), " ")

    // test if field bodies are the same
    if body2 != body {
        t.Errorf("body not same: %q - %q", body, body2)
    }
}
*/

func TestSignWithDomain(t *testing.T) {

	in, err := os.Open("test/in.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	message, err := mail.ReadMessage(in)
	if err != nil {
		t.Fatal(err)
	}

	domain, err := ReadDomain("emailfabric.com", "test", "test/test.rsa")
	if err != nil {
		t.Fatal(err)
	}

	sig := NewSignature(domain)

	// step 1
	_, err = io.Copy(sig.BodyWriter(), message.Body)
	if err != nil {
		t.Fatal(err)
	}

	// step 2
	err = sig.SignHeader(message.Header)
	if err != nil {
		t.Fatal(err)
	}

    // note that the order of headers in h= is non-determistic
    
	out, err := os.Create("test/out.txt")
	if err != nil {
		t.Fatal(err)
	}
	sig.WriteTo(out)
    out.Close()
    
    fmt.Println("If opendkim is installed, run the following command to test the signature:")
    fmt.Println("")
    fmt.Println("    cat test/out.txt test/in.txt | opendkim-testmsg")
    fmt.Println("")
}
