package main

import (
	"io/ioutil"
	"log"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/gitirabassi/libvault"
)

func main() {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	sshEngine, err := cli.SSH("ssh", false)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	public, err := sshEngine.GetPublicKey()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	spew.Printf("publickey: %v\n", public)
	err = ioutil.WriteFile("ssh_key.pub", []byte(public), 0644)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
