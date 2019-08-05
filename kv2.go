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

// NewSecretBackend is safe and idempotent way of creating a secret backend if it doesn't already exist
// func (c *Client) NewSecretBackend(path, backendType string) error {
// 	mounts, err := cli.Sys().ListMounts()
// 	if err != nil {
// 		return err
// 	}
// 	v, ok := mounts[fmt.Sprintf("%s/", path)]
// 	if ok {
// 		fmt.Printf("%s/ already exist as a backend... returning\n")
// 		return nil
// 	}
// 	mountOptions := &api.MountInput{
// 		Type:        backendType,
// 		Description: "Backend created with libvault",
// 		SealWrap:    false,
// 		Local:       false,
// 		// Options:     map[string]string{
// 		// 	"versin": "1",o
// 		// },
// 		Config: api.MountConfigInput{
// 			DefaultLeaseTTL: "0",
// 			MaxLeaseTTL:     "0",
// 			ForceNoCache:    false,
// 		},
// 	}

// 	err = cli.Sys().Mount(path, mountOptions)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
