package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/louisevanderlith/kong/tokens"
	"os"
)

func DecodeToken(raw string, prvKey *rsa.PrivateKey) (tokens.Accessor, error) {
	tkn, err := hex.DecodeString(raw)

	if err != nil {
		return nil, err
	}

	dcryptd, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, prvKey, tkn, []byte("access"))

	if err != nil {
		return nil, err
	}

	result := tokens.AccessToken{}
	err = json.Unmarshal(dcryptd, &result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

func savePEMKey(filename string, blck *pem.Block) error {
	outFile, err := os.Create(filename)

	if err != nil {
		return err
	}

	defer outFile.Close()

	err = pem.Encode(outFile, blck)

	if err != nil {
		return err
	}

	return nil
}

func savePrivatePEMKey(filename string, key *rsa.PrivateKey) error {
	blckBytes, err := x509.MarshalPKCS8PrivateKey(key)

	if err != nil {
		return err
	}

	blck := &pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   blckBytes, //x509.MarshalPKCS1PrivateKey(key),
	}

	return savePEMKey(filename, blck)
}

func savePublicPEMKey(filename string, key *rsa.PublicKey) error {
	bits, err := x509.MarshalPKIXPublicKey(key)

	if err != nil {
		return err
	}

	blck := &pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   bits,
	}

	return savePEMKey(filename, blck)
}
