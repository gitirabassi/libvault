package main

import (
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/gitirabassi/libvault"
)

type User struct {
	Nickname   string `mapstructure:"nickname"`
	Password   string `mapstructure:"password"`
	Email      string `mapstructure:"email"`
	PrivateKey string `mapstructure:"private_key"`
}

func main() {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	s := &User{
		Nickname:   "gitirabassi",
		Password:   "foggettaboudit",
		Email:      "giacomo@tirabassi.eu",
		PrivateKey: "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
	}
	err = cli.KV2("secret").Put("users/giacomo", s)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	receving := &User{}
	err = cli.KV2("secret").Get("users/giacomo", receving)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	spew.Printf("input: %#v\noutput: %#v\n", *s, *receving)
	if *s != *receving {
		log.Println("Data put in is different than the one that we got out")
		os.Exit(1)
	}
}
