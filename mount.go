package libvault

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

func (c *Client) doesMountExist(path string) (bool, error) {
	mounts, err := c.client.Sys().ListMounts()
	if err != nil {
		return false, err
	}
	_, ok := mounts[fmt.Sprintf("%s/", path)]
	if ok {
		return true, nil
	}
	return false, nil
}

// Mount mounts a backend if not mounted already (it doesn't try to reconfigure an already mounted object)
func (c *Client) mount(path string, cfg *api.MountInput, createIfdoesntExist bool) error {
	exist, err := c.doesMountExist(path)
	if err != nil {
		return err
	}
	if exist {
		return nil
	}
	if !createIfdoesntExist && !exist {
		return fmt.Errorf("The backend is not mounted")
	}
	err = c.client.Sys().Mount(path, cfg)
	if err != nil {
		return err
	}
	exist, err = c.doesMountExist(path)
	if err != nil {
		return err
	}
	if !exist {
		return fmt.Errorf("Even tho the Vault sais that it mounted it's not showing up when listing available mounts")
	}
	return nil
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
