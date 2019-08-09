package main

import (
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/gitirabassi/libvault"
)

// User is just a fake user-defined struct of data
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
	kvengine, err := cli.KV("kv1", false, true)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	err = kvengine.Put("users/giacomo", s)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	receving := &User{}
	err = kvengine.Get("users/giacomo", receving)
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
