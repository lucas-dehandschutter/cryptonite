package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"os"
)

func EncryptFile(ctx context.Context, filepath string, key []byte) error {
	infile, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer infile.Close()

	outfile, err := os.Create(filepath + ".enc")
	if err != nil {
		return err
	}
	defer outfile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	aesCtr := cipher.NewCTR(block, nonce)
	writer := &cipher.StreamWriter{S: aesCtr, W: outfile}
	buf := make([]byte, 1024)
	for {
		n, err := infile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		if n < 1024 || ctx.Err() != nil {
			if _, err := writer.Write(buf[:n]); err != nil {
				return err
			}
			break
		}

		if _, err := writer.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func DecryptFile(ctx context.Context, filepath string, key []byte) error {
	infile, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer infile.Close()

	outfile, err := os.Create(filepath + ".dec")
	if err != nil {
		return err
	}
	defer outfile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, 16)
	if _, err = io.ReadFull(infile, nonce); err != nil {
		return err
	}

	aesCtr := cipher.NewCTR(block, nonce)
	reader := &cipher.StreamReader{S: aesCtr, R: infile}
	buf := make([]byte, 1024)
	for {
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		if n < 1024 || ctx.Err() != nil {
			if _, err := outfile.Write(buf[:n]); err != nil {
				return err
			}
			break
		}

		if _, err := outfile.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// transformPassword takes a password string, hashes it using SHA-256, and returns the resulting byte slice.
func transformPassword(password string) []byte {
	hash := sha256.New()
	hash.Write([]byte(password))
	key := hash.Sum(nil)
	return key
}
