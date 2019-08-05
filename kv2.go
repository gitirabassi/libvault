package libvault

import "fmt"

// KV2 represents the KV store in vault
type KV2 struct {
	c    *Client
	path string
	// version string
}

// KV2 makes the user enter in the KV space
func (c *Client) KV2(path string) *KV2 {
	return &KV2{
		c:    c,
		path: path,
	}
}

// Put is a parity funcion with `vault kv put`
func (k *KV2) Put(secretName string, input interface{}) error {
	secretPath := fmt.Sprintf("%s/data/%s", k.path, secretName)
	return k.c.writeOp(secretPath, input, nil, true)
}

// Get is the parithy function with `vualt kv get` (ONLY HANDLING V2 kv)
func (k *KV2) Get(secretName string, output interface{}) error {
	secretPath := fmt.Sprintf("%s/data/%s", k.path, secretName)
	return k.c.readOp(secretPath, output, true)
}

// Delete is the parity function with `vuault kv delete`
func (k *KV2) Delete(secretName string) error {
	secretPath := fmt.Sprintf("%s/data/%s", k.path, secretName)
	return k.c.deleteOp(secretPath)
}
