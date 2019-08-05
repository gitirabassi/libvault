package libvault_test

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
)

const (
	vaultToken   = "superSecretToken"
	vaultImage   = "docker.io/library/vault"
	vaultVersion = "1.2.0"
)

func TestMain(m *testing.M) {
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.Run(vaultImage, vaultVersion, []string{fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", vaultToken)})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	os.Setenv("VAULT_ADDR", fmt.Sprintf("http://127.0.0.1:%v", resource.GetPort("8200/tcp")))
	os.Setenv("VAULT_TOKEN", vaultToken)
	defer os.Unsetenv("VAULT_ADDR")
	defer os.Unsetenv("VAULT_TOKEN")
	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		cli, err := api.NewClient(api.DefaultConfig())
		if err != nil {
			return fmt.Errorf("Cannot create Vault Client: %v", err)
		}
		status, err := cli.Sys().InitStatus()
		if err != nil {
			return err
		}
		if status != true {
			return fmt.Errorf("Vault not ready yet")
		}
		return nil
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	code := 0
	if err == nil {
		code = m.Run()
	}

	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(resource); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}
