package dkim

import (
	"encoding/base64"
    "fmt"
	"io"
	"net/mail"
	"os"
	"testing"
)

func TestHeaderHash(t *testing.T) {
	/*
	   opendkim-testmsg -d emailfabric.com -k test/test.rsa -s test -C < test/in.txt > test/out-opendkim.txt
	   opendkim-testmsg < test/out-opendkim.txt

	   DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/simple; d=emailfabric.com;
	   	s=test; t=1458847942;
	   	bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
	   	h=From:To:Subject:Date;
	   	b=VIvfqAyWAM6M7i/vZkKR8s7YE2GIgJFjEEE0LHBaZhPNbKpV4F1IuW3l55JIwn7jc
	   	 UhmNUdFNcII3Hdwv/9XU/740luPsxl658a7Yft4Lu8g3QzyR/Rrh7tkB2g68fQMVV0
	   	 TatLnLqQC9By5dmzknf/avIwIB5xJPflIimHAm5o=
	   From: Joe SixPack <joe@football.example.com>
	   To: Suzie Q <suzie@shopping.example.net>
	   Subject: Is dinner ready?
	   Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
	   Message-ID: <20030712040037.46341.5F8J@football.example.com>
	*/
	hh := newRelaxedHeaderHash(Hash.New())
	hh.AddHeader("From", "Joe SixPack <joe@football.example.com>")
	hh.AddHeader("To", "Suzie Q <suzie@shopping.example.net>")
	hh.AddHeader("Subject", "Is dinner ready?")
	hh.AddHeader("Date", "Fri, 11 Jul 2003 21:00:37 -0700 (PDT)")
	sum := hh.Sum("v=1; a=rsa-sha256; c=relaxed/simple; d=emailfabric.com; s=test; t=1458847942; bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; h=From:To:Subject:Date; b=")

	domain, err := ReadDomain("emailfabric.com", "test", "test/test.rsa")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := domain.sign(sum)
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(signed) !=
		"VIvfqAyWAM6M7i/vZkKR8s7YE2GIgJFjEEE0LHBaZhPNbKpV4F1IuW3l55JIwn7jc"+
			"UhmNUdFNcII3Hdwv/9XU/740luPsxl658a7Yft4Lu8g3QzyR/Rrh7tkB2g68fQMVV0"+
			"TatLnLqQC9By5dmzknf/avIwIB5xJPflIimHAm5o=" {
		t.Errorf("Unexpected signed header hash")
	}
}

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
