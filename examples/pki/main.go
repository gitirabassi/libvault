package main

import (
	"log"
	"os"

	"github.com/gitirabassi/libvault"
)

func main() {
	cli, err := libvault.NewClient()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	pkiEngine, err := cli.PKI("cluster/staging/etcd", true)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	conf := &libvault.PKIConfig{
		Organization:  "InfluxData",
		StreetAddress: "799 Market Street Suite 400",
		Locality:      "San Francisco",
		Province:      "California",
		PostalCode:    "94103",
		Country:       "USA",
	}
	err = pkiEngine.Root(conf)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	err = pkiEngine.CreateDefaultRoles("etcd-1", "etcd-2", "etcd-3")
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
