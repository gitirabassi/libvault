/*
Copyright © 2018, Oracle and/or its affiliates. All rights reserved.

The Universal Permissive License (UPL), Version 1.0
*/

package main

import (
	"flag"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	pb "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

func main() {
	socketFile := flag.String("socketFile", "unix:///tmp/kms-plugin.sock", "socket file that gRpc server listens to")
	transitMountPath := flag.String("transitMountPath", "", "transit path mount to be used")
	keyNames := flag.String("keyNames", "", "transit keys to be used when encrypting or decrypting data: multiple are used for migrating from one key to another. Encryption is done with the first one, decryption is tried with all of them (comma separated list)")
	clientMode := flag.Bool("clientMode", false, "When you need to test the server you can use `kms-plugin --clientMode=on --socketFile=unix:///tmp/kms-plugin.sock`")

	flag.Parse()

	if *socketFile == "" {
		log.Fatal("socketFile parameter not specified")
	}

	if *clientMode {
		err := runClient(*socketFile)
		if err != nil {
			log.Fatalf("Failed to run client %s: %v", *socketFile, err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *transitMountPath == "" {
		log.Fatal("transitMountPath parameter not specified")
	}
	if *keyNames == "" {
		log.Fatal("keyNames parameter not specified")
	}

	keyList := strings.SplitN(*keyNames, ",", -1)
	// Starting TCP server
	err := unix.Unlink(*socketFile)
	if err != nil {
		log.Fatalf("failed to unlink %s: %v", socketFile, err)
	}
	listener, err := net.Listen("unix", *socketFile)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	kmsServer, err := NewKMSServer(*transitMountPath, keyList)
	if err != nil {
		log.Fatalf("failed to initialize vault service, error: %v", err)
	}

	s := grpc.NewServer()
	pb.RegisterKeyManagementServiceServer(s, kmsServer)
	log.Infof("Version: %s, runtimeName: %s, RuntimeVersion: %s", "v1beta1", "vault", "0.1.0")
	if err := s.Serve(listener); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
