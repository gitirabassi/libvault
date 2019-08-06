package libvault_test

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gitirabassi/libvault"
)

type User struct {
	Nickname   string `mapstructure:"nickname"`
	Password   string `mapstructure:"password"`
	Email      string `mapstructure:"email"`
	PrivateKey string `mapstructure:"private_key"`
}

func TestKv2(t *testing.T) {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		t.FailNow()
	}
	input := &User{
		Nickname:   "gitirabassi",
		Password:   "foggettaboudit",
		Email:      "giacomo@tirabassi.eu",
		PrivateKey: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
	}
	kvEngine, err := cli.KV("secret", true, true)
	if err != nil {
		log.Println(err)
		t.FailNow()
	}
	kvEngine2, err := cli.KV("secret", true, true)
	if err != nil {
		log.Println(err)
		t.FailNow()
	}
	err = kvEngine.Put("users/giacomo", input)
	if err != nil {
		log.Println(err)
		t.FailNow()
	}
	receving := &User{}
	err = kvEngine2.Get("users/giacomo", receving)
	if err != nil {
		log.Println(err)
		t.FailNow()
	}
	assert.Equal(t, input, receving)
}
