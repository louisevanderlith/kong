package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
)

var (
	//PrivateKey is the private key used for signing tokens
	PrivateKey *rsa.PrivateKey
)

const (
	privateKeyFilename string = "sign_key.pem"
	publicKeyFilename  string = "sign_pub.pem"
)

// Initialize creates a new Public/Private key pair for signing authentication requests, if no other keys exist
func Initialize(path string) error {
	key, err := loadPrivateKey(path)

	if err != nil {
		return err
	}

	PrivateKey = key

	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	privPath := path + privateKeyFilename
	pubPath := path + publicKeyFilename
	_, err := os.Stat(privPath)
	if os.IsNotExist(err) {
		return generateKeyPair(path)
	}

	if err != nil {
		log.Println(err)
		return nil, err
	}

	privDer, err := ioutil.ReadFile(privPath)

	if err != nil {
		return nil, err
	}

	privBlock, _ := pem.Decode(privDer)

	if privBlock == nil {
		return nil, errors.New("private block is nil")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)

	if err != nil {
		return nil, err
	}

	rsaPriv := privKey.(*rsa.PrivateKey)

	err = rsaPriv.Validate()

	if err != nil {
		return nil, err
	}

	pubDer, err := ioutil.ReadFile(pubPath)

	if err != nil {
		return nil, err
	}

	pubBlock, _ := pem.Decode(pubDer)

	if pubBlock == nil {
		return nil, errors.New("public block is nil")
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)

	if err != nil {
		return nil, err
	}

	rsaPriv.PublicKey = *pubKey.(*rsa.PublicKey)

	return rsaPriv, nil
}

//generateKeyPair
func generateKeyPair(path string) (*rsa.PrivateKey, error) {
	reader := rand.Reader

	privKey, err := rsa.GenerateKey(reader, 2048)

	if err != nil {
		return nil, err
	}

	err = privKey.Validate()
	if err != nil {
		return nil, err
	}

	err = savePrivatePEMKey(path+privateKeyFilename, privKey)

	if err != nil {
		return nil, err
	}

	err = savePublicPEMKey(path+publicKeyFilename, &privKey.PublicKey)

	if err != nil {
		return nil, err
	}

	return privKey, nil
}
