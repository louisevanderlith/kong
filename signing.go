package kong

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/louisevanderlith/kong/tokens"
	"io/ioutil"
	"os"
)

const (
	privateKeyFilename string = "sign_key.pem"
	publicKeyFilename  string = "sign_pub.pem"
)

//EncodeClaims returns a base64 Encrypted token
func EncodeClaims(key []byte, claims tokens.Claimer) (string, error) {
	bits, err := json.Marshal(claims)

	if err != nil {
		return "", err
	}

	if len(key) != 32 {
		return "", errors.New("requires 32bit key")
	}

	c, err := aes.NewCipher(key)

	if err != nil {
		return "", nil
	}

	gcm, err := cipher.NewGCM(c)

	if err != nil {
		return "", nil
	}

	nonce := generateKey(gcm.NonceSize())

	smlBits := base64.URLEncoding.EncodeToString(bits)

	ciphertext := gcm.Seal(nonce, nonce, []byte(smlBits), nil)

	if err != nil {
		return "", err
	}

	val := base64.URLEncoding.EncodeToString(ciphertext)

	return val, nil
}

//DecodeToken return Claims from the base64 token
func DecodeToken(key []byte, token string) (tokens.Claimer, error) {
	if len(key) != 32 {
		return nil, errors.New("requires 32bit key")
	}

	o, err := base64.URLEncoding.DecodeString(token)

	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	if len(token) < nonceSize {
		return nil, errors.New("token size invalid")
	}

	nonce, ciphertext := o[:nonceSize], o[nonceSize:]

	dcryptd, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return nil, err
	}

	jobj, err := base64.URLEncoding.DecodeString(string(dcryptd))

	if err != nil {
		return nil, err
	}

	result := make(tokens.Claims)
	err = json.Unmarshal(jobj, &result)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Initialize creates a new Public/Private key pair for signing authentication requests, if no other keys exist
func InitializeCert(path string, saveCerts bool) (*rsa.PrivateKey, error) {
	key, err := loadPrivateKey(path, saveCerts)

	if err != nil {
		return nil, err
	}

	return key, nil
}

func loadPrivateKey(path string, saveCerts bool) (*rsa.PrivateKey, error) {
	privPath := path + privateKeyFilename
	pubPath := path + publicKeyFilename
	_, err := os.Stat(privPath)
	if os.IsNotExist(err) {
		return generateKeyPair(path, saveCerts)
	}

	if err != nil {
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
func generateKeyPair(path string, saveCerts bool) (*rsa.PrivateKey, error) {
	reader := rand.Reader

	privKey, err := rsa.GenerateKey(reader, 4096)

	if err != nil {
		return nil, err
	}

	err = privKey.Validate()
	if err != nil {
		return nil, err
	}

	if saveCerts {
		err = savePrivatePEMKey(path+privateKeyFilename, privKey)

		if err != nil {
			return nil, err
		}

		err = savePublicPEMKey(path+publicKeyFilename, &privKey.PublicKey)

		if err != nil {
			return nil, err
		}
	}

	return privKey, nil
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
