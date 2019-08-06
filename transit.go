package libvault

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/hashicorp/vault/api"
)

// Transit represents the transit secret backend in vault
type Transit struct {
	c       *Client
	path    string
	keyName string
	keyType string
}

// Key is how a new key is created/configured/exported in vault
type Key struct {
	AllowPlaintextBackup bool               `mapstructure:"allow_plaintext_backup"`
	Name                 string             `mapstructure:"name"`
	DeletionAllowed      bool               `mapstructure:"deletion_allowed"`
	Derived              bool               `mapstructure:"derived"`
	Exportable           bool               `mapstructure:"exportable"`
	Keys                 map[string]KeySpec `mapstructure:"keys"`
	LatestVersion        int                `mapstructure:"latest_version"`
	MinAvailableVersion  int                `mapstructure:"min_available_version"`
	MinDecryptionVersion int                `mapstructure:"min_decryption_version"`
	MinEncryptionVersion int                `mapstructure:"min_encryption_version"`
	SupportsDecryption   bool               `mapstructure:"supports_decryption"`
	SupportsDerivation   bool               `mapstructure:"supports_derivation"`
	SupportsEncryption   bool               `mapstructure:"supports_encryption"`
	SupportsSigning      bool               `mapstructure:"supports_signing"`
	Type                 string             `mapstructure:"type"`
}

// KeySpec represents the key specification for a specific version
type KeySpec struct {
	CreationTime string `mapstructure:"creation_time"`
	Name         string `mapstructure:"name"`
	PublicKey    string `mapstructure:"public_key"`
}

// Transit makes the user enter in the Transit space
func (c *Client) Transit(path, keyName string, createIfDoesntExist bool) (*Transit, error) {
	mountOptions := &api.MountInput{
		Type:        "transit",
		Description: defaultMountDescription,
	}
	err := c.mount(path, mountOptions, createIfDoesntExist)
	if err != nil {
		return nil, err
	}

	// Key Creation
	//TODO: check if the key already exist
	keyPath := filepath.Join(path, "keys", keyName)
	keyInput := &Key{
		//TODO: being able to change this
		Type: "rsa-4096",
	}
	err = c.writeOp(keyPath, keyInput, nil, false)
	if err != nil {
		return nil, err
	}
	output := &Key{}
	err = c.readOp(keyPath, output, false)
	if err != nil {
		return nil, err
	}
	return &Transit{
		c:       c,
		path:    path,
		keyName: output.Name,
		keyType: output.Type,
	}, nil
}

// KeyType returns the type of the key used
func (t *Transit) KeyType() string {
	return t.keyType
}

// GetPublicKey obtains the public key for the specified key
func (t *Transit) GetPublicKey() (string, error) {
	keyPath := filepath.Join(t.path, "keys", t.keyName)
	output := &Key{}
	err := t.c.readOp(keyPath, output, false)
	if err != nil {
		return "", err
	}
	return output.Keys[strconv.Itoa(output.LatestVersion)].PublicKey, nil
}

// Unencrypted is the plaintext side!
type Unencrypted struct {
	Plaintext string `mapstructure:"plaintext"`
}

// Encrypted is used to unmarshal ouput from the Encrypt or input for the Decrypt function
type Encrypted struct {
	Ciphertext string `mapstructure:"ciphertext"`
}

// EncryptBytes is used to encrypt data that is already serialized
func (t *Transit) EncryptBytes(plaintext []byte) (string, error) {
	return t.encryptBytes(plaintext)
}

func (t *Transit) encryptBytes(plaintext []byte) (string, error) {
	encryptPath := filepath.Join(t.path, "encrypt", t.keyName)
	input := &Unencrypted{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	output := &Encrypted{}
	err := t.c.writeOp(encryptPath, input, output, false)
	if err != nil {
		return "", err
	}
	return output.Ciphertext, nil
}

// DecryptToBytes is used to encrypt data that is already serialized
func (t *Transit) DecryptToBytes(ciphertext string) ([]byte, error) {
	return t.decryptToBytes(ciphertext)
}

func (t *Transit) decryptToBytes(ciphertext string) ([]byte, error) {
	decryptPath := filepath.Join(t.path, "decrypt", t.keyName)
	input := &Encrypted{
		Ciphertext: ciphertext,
	}
	output := &Unencrypted{}
	err := t.c.writeOp(decryptPath, input, output, false)
	if err != nil {
		return nil, err
	}
	bytes, err := base64.StdEncoding.DecodeString(output.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("Couldn't decode base64 plaintext: %v", err)
	}
	return bytes, nil
}

// HMACInput are the required paramethers to compute the HMAC of data
type HMACInput struct {
	Input string `mapstructure:"input"`
}

// HMACOutput is the result of the HMAC function in vault
type HMACOutput struct {
	HMAC string `mapstructure:"hmac"`
}

// HMAC computes the hmac of a given data
func (t *Transit) HMAC(data string) (string, error) {
	hashPath := filepath.Join(t.path, "hmac", t.keyName, "sha2-256")
	input := &HMACInput{
		Input: base64.StdEncoding.EncodeToString([]byte(data)),
	}
	output := &HMACOutput{}
	err := t.c.writeOp(hashPath, input, output, false)
	if err != nil {
		return "", err
	}
	return output.HMAC, nil
}

// SignInput are the paramethers necessary to get a signature of data
type SignInput struct {
	Input               string `mapstructure:"input"`
	MarshalingAlgorithm string `mapstructure:"marshaling_algorithm"`
	SignatureAlgorithm  string `mapstructure:"signature_algorithm"`
	Prehashed           bool   `mapstructure:"prehashed"`
}

// SignOutput is the actual signature of the previously passed data
type SignOutput struct {
	Signature string `mapstructure:"signature"`
}

// Sign is used to get a signature for a given piece of information
func (t *Transit) Sign(data string) (string, error) {
	signPath := filepath.Join(t.path, "sign", t.keyName, "sha2-256")
	sum := sha256.Sum256([]byte(data))
	input := &SignInput{
		Input:               base64.StdEncoding.EncodeToString(sum[:]),
		MarshalingAlgorithm: "jws",
		SignatureAlgorithm:  "pkcs1v15",
		Prehashed:           true,
	}
	output := &SignOutput{}
	err := t.c.writeOp(signPath, input, output, false)
	if err != nil {
		return "", err
	}
	return output.Signature, nil
}

// VerifySignInput are the necessary parametheus to verify a signature obtained with vault
type VerifySignInput struct {
	Input               string `mapstructure:"input"`
	Signature           string `mapstructure:"signature"`
	MarshalingAlgorithm string `mapstructure:"marshaling_algorithm"`
	SignatureAlgorithm  string `mapstructure:"signature_algorithm"`
	Prehashed           bool   `mapstructure:"prehashed"`
}

// VerifyOutput is the outcome of a verification call
type VerifyOutput struct {
	Valid bool `mapstructure:"valid"`
}

//VerifySignature is used to verify a signature previously created with vault: signature is of type "vault:v1:abcdefg..."
func (t *Transit) VerifySignature(data, signature string) error {
	verifyPath := filepath.Join(t.path, "verify", t.keyName, "sha2-256")
	sum := sha256.Sum256([]byte(data))
	input := &VerifySignInput{
		Input:               base64.StdEncoding.EncodeToString(sum[:]),
		Signature:           signature,
		MarshalingAlgorithm: "jws",
		SignatureAlgorithm:  "pkcs1v15",
		Prehashed:           true,
	}
	output := &VerifyOutput{}
	err := t.c.writeOp(verifyPath, input, output, false)
	if err != nil {
		return err
	}
	if !output.Valid {
		return fmt.Errorf("Signature is not valid")
	}
	return nil
}

// VerifyHMACInput are the necessary parametheus to verify an HMAC obtained with vault
type VerifyHMACInput struct {
	Input               string `mapstructure:"input"`
	HMAC                string `mapstructure:"hmac"`
	MarshalingAlgorithm string `mapstructure:"marshaling_algorithm"`
	SignatureAlgorithm  string `mapstructure:"signature_algorithm"`
	Prehashed           bool   `mapstructure:"prehashed"`
}

//VerifyHMAC is used to verify a signature previously created with vault
func (t *Transit) VerifyHMAC(data, hmac string) error {
	verifyPath := filepath.Join(t.path, "verify", t.keyName, "sha2-256")
	input := &VerifyHMACInput{
		Input:               base64.StdEncoding.EncodeToString([]byte(data)),
		HMAC:                hmac,
		MarshalingAlgorithm: "jws",
		SignatureAlgorithm:  "pkcs1v15",
		Prehashed:           false,
	}
	output := &VerifyOutput{}
	err := t.c.writeOp(verifyPath, input, output, false)
	if err != nil {
		return err
	}
	if !output.Valid {
		return fmt.Errorf("Signature is not valid")
	}
	return nil
}
