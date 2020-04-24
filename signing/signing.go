package signing

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

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
