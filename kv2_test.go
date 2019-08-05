package libvault_test

import (
	"log"
	"testing"

	"github.com/gitirabassi/libvault"
)

type User struct {
	Nickname   string `mapstructure:"nickname"`
	Password   string `mapstructure:"password"`
	Email      string `mapstructure:"email"`
	PrivateKey string `mapstructure:"private_key"`
}

func TestingKv2(t *testing.T) {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		t.Fail()
	}
	input := &User{
		Nickname:   "gitirabassi",
		Password:   "foggettaboudit",
		Email:      "giacomo@tirabassi.eu",
		PrivateKey: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
	}
	err = cli.KV2("secret").Put("users/giacomo", input)
	if err != nil {
		log.Println(err)
		t.Fail()
	}
	receving := &User{}
	err = cli.KV2("secret").Get("users/giacomo", receving)
	if err != nil {
		log.Println(err)
		t.Fail()
	}
	if *input != *receving {
		log.Println("Data put in is different than the one that we got out")
		t.Fail()
	}
}
