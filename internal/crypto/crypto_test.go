package crypto

import (
	"context"
	"gopkg.in/loremipsum.v1"
	"log"
	"os"
	"testing"
)

func setupSuite(tb testing.TB) func(tb testing.TB) {
	log.Println("setup test suite")
	log.Println("generate test data")
	loremIP := loremipsum.New()
	text := loremIP.Paragraphs(10)
	err := os.WriteFile("testdata/test", []byte(text), os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
	}
	// Return a function to teardown the test
	return func(tb testing.TB) {
		log.Println("teardown suite")
	}
}

func TestEncryptFile(t *testing.T) {
	teardown := setupSuite(t)
	defer teardown(t)
	err := EncryptFile(context.Background(), "testdata/test", transformPassword("password"))
	if err != nil {
		t.Fatal(err)
	}
}
