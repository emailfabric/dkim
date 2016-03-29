package dkim

import (
	"fmt"
	"testing"
)

//sample := regexp.MustCompile("([^\r])\n").ReplaceAllString(sample2, "$1\r\n")

func xTestGenKey(t *testing.T) {
	pem, pub, err := GenerateKeyPair(1024)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(pem))
	fmt.Printf("v=DKIM1;p=%s\n", pub)
}
