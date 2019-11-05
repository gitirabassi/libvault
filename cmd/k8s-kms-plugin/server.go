package main

import (
	"fmt"

	"github.com/gitirabassi/libvault"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	pb "k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

// kmsServer is used to implement kms plugin grpc server.
type kmsServer struct {
	vault      *libvault.Client
	keyEngines []*libvault.Transit
}

// NewKMSServer is used to instatiate a kmsServer
func NewKMSServer(transitMountPath string, keyList []string) (*kmsServer, error) {
	cli, err := libvault.NewClient()
	if err != nil {
		return nil, err
	}
	keyEngines := make([]*libvault.Transit, 0)
	for _, key := range keyList {
		transitEngine, err := cli.Transit(transitMountPath, key, false)
		if err != nil {
			return nil, err
		}
		keyEngines = append(keyEngines, transitEngine)
	}
	ks := &kmsServer{
		vault:      cli,
		keyEngines: keyEngines,
	}
	return ks, nil
}

func (s *kmsServer) Version(ctx context.Context, request *pb.VersionRequest) (*pb.VersionResponse, error) {
	log.Infof("Version information requested by API server")
	return &pb.VersionResponse{Version: "v1beta1", RuntimeName: "vault", RuntimeVersion: "0.1.0"}, nil
}

func (s *kmsServer) Decrypt(ctx context.Context, request *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	for i, keyEngine := range s.keyEngines {
		plain, err := keyEngine.DecryptToBytes(string(request.Cipher))
		if err != nil {
			log.Warnf("Decrypt with key n. %v error: %v", i, err)
		}
		return &pb.DecryptResponse{Plain: plain}, nil
	}
	return nil, fmt.Errorf("Decryption failed with all keys")
}

func (s *kmsServer) Encrypt(ctx context.Context, request *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	cipher, err := s.keyEngines[0].EncryptBytes(request.Plain)
	if err != nil {
		log.Warnf("Encrypt error: %v", err)
		return nil, err
	}
	return &pb.EncryptResponse{Cipher: []byte(cipher)}, nil
}
