package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	pb "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

var (
	testData = []byte("I'm the best because this will be encrypted")
)

func runClient(socketAddr string) error {
	connection, err := grpc.Dial(socketAddr, grpc.WithInsecure(), grpc.WithTimeout(30*time.Second), grpc.WithDialer(unixDial))
	defer connection.Close()
	if err != nil {
		fmt.Println("Connection to KMS plugin failed, error: %v", err)
	}

	kmsClient := pb.NewKeyManagementServiceClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println(fmt.Sprintf("Original message: %s", testData))
	request := &pb.EncryptRequest{Plain: testData, Version: "v1beta1"}
	response, err := kmsClient.Encrypt(ctx, request)
	if err != nil {
		return fmt.Errorf("request error: %v", err)
	}

	cipher := response.Cipher
	decryptReq := &pb.DecryptRequest{Cipher: cipher, Version: "v1beta1"}

	fmt.Println(fmt.Sprintf("Encrypt response: %s", response.Cipher))
	decryptRes, _ := kmsClient.Decrypt(ctx, decryptReq)
	fmt.Println(fmt.Sprintf("Decrypt response: %s", decryptRes.Plain))
	return nil
}

// This dialer explicitly ask gRPC to use unix socket as network.
func unixDial(addr string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("unix", addr, timeout)
}
