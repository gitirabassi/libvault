package libvault

import (
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// This file is the extenstion for https://github.com/dgrijalva/jwt-go to use vault to sign

var (
	// SigningMethodVaultRS256 implements the SigningMethod interface with alg RS256
	SigningMethodVaultRS256 *SigningMethodVault
	// SigningMethodVaultES256 implements the SigningMethod interface with alg ES256
	SigningMethodVaultES256 *SigningMethodVault
)

func init() {
	// RS256
	SigningMethodVaultRS256 = &SigningMethodVault{"RS256", []string{"rsa-2048", "rsa-4096"}}
	jwt.RegisterSigningMethod(SigningMethodVaultRS256.Alg(), func() jwt.SigningMethod {
		return SigningMethodVaultRS256
	})
	// ES256
	SigningMethodVaultES256 = &SigningMethodVault{"ES256", []string{"ecdsa-p256"}}
	jwt.RegisterSigningMethod(SigningMethodVaultES256.Alg(), func() jwt.SigningMethod {
		return SigningMethodVaultES256
	})

}

// SigningMethodVault is the type that implements the SigningMethod interface (https://godoc.org/github.com/dgrijalva/jwt-go#SigningMethod)
type SigningMethodVault struct {
	alg             string
	allowedKeyTypes []string
}

// Alg will return the JWT header algorithm identifier this method is configured for
func (r *SigningMethodVault) Alg() string {
	return r.alg
}

// Sign implements the Sign method from jwt.SigningMethod. Key must be of type libvault.Transit with the right alg key configured (rsa-2048/4096 for RS256 or edcsa-p256 for ES256)
func (r *SigningMethodVault) Sign(signingString string, key interface{}) (string, error) {
	t := Transit{}
	switch k := key.(type) {
	case Transit:
		t = k
	default:
		return "", jwt.ErrInvalidKey
	}

	rightKey := contains(r.allowedKeyTypes, t.KeyType())
	if !rightKey {
		return "", fmt.Errorf("wrong key type configured in libvault.Transit, want one of: %v, got: %v", r.allowedKeyTypes, t.KeyType())
	}
	return t.Sign(signingString)
}

// Verify implements the Verify method from jwt.SigningMethod. Key must be of type libvault.Transit with the right alg key configured (rsa-2048/4096 for RS256 or edcsa-p256 for ES256)
func (r *SigningMethodVault) Verify(signingString, signature string, key interface{}) error {
	t := Transit{}
	switch k := key.(type) {
	case Transit:
		t = k
	default:
		return jwt.ErrInvalidKey
	}

	rightKey := contains(r.allowedKeyTypes, t.KeyType())
	if !rightKey {
		return fmt.Errorf("wrong key type configured in libvault.Transit, want one of: %v, got: %v", r.allowedKeyTypes, t.KeyType())
	}
	return t.VerifySignature(signingString, signature)
}

func contains(allowed []string, key string) bool {
	for _, a := range allowed {
		if a == key {
			return true
		}
	}
	return false
}

// CutVaultPrefix is used to remove `vault:v2:` from either signatures and hmac
func CutVaultPrefix(sig string) string {
	list := strings.SplitN(sig, ":", 3)
	return list[2]
}
