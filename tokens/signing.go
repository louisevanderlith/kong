package tokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type Signer interface {
	Sign(token Claims, exp time.Duration) (string, error)
}

//GenerateKey returns a key with the specified length
func GenerateKey(len int) []byte {
	k := make([]byte, len)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}

	return k
}

//Issue Claims will add IssuedAt & ExpiresAt claims before encoding
func IssueClaims(key []byte, claims Claims, exp time.Duration) (string, error) {
	iat := time.Now()
	claims.AddClaim(KongIssued, iat)
	claims.AddClaim(KongExpired, iat.Add(time.Minute*exp))

	return EncodeClaims(key, claims)
}

//EncodeClaims returns a base64 Encrypted token
func EncodeClaims(key []byte, claims Claims) (string, error) {
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

	nonce := GenerateKey(gcm.NonceSize())

	smlBits := base64.URLEncoding.EncodeToString(bits)

	ciphertext := gcm.Seal(nonce, nonce, []byte(smlBits), nil)

	if err != nil {
		return "", err
	}

	val := base64.URLEncoding.EncodeToString(ciphertext)

	return val, nil
}

//DecodeToken return Claims from the base64 token
func DecodeToken(key []byte, token string, result Claims) error {
	if len(key) != 32 {
		return errors.New("requires 32bit key")
	}

	o, err := base64.URLEncoding.DecodeString(token)

	if err != nil {
		return err
	}

	c, err := aes.NewCipher(key)

	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()

	if len(token) < nonceSize {
		return errors.New("token size invalid")
	}

	nonce, ciphertext := o[:nonceSize], o[nonceSize:]

	dcryptd, err := gcm.Open(nil, nonce, ciphertext, nil)

	if err != nil {
		return err
	}

	jobj, err := base64.URLEncoding.DecodeString(string(dcryptd))

	if err != nil {
		return err
	}

	return json.Unmarshal(jobj, &result)
}