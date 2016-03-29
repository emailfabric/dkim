package dkim

import (
	"encoding/base64"
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

func TestHeaderHashValue(t *testing.T) {
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
	signed, err := domain.Sign(sum)
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
