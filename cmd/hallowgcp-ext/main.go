package main

import (
	"context"
	"crypto/rand"
	"log"
	"net"

	kms "cloud.google.com/go/kms/apiv1"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/flynn/hallowgcp/pkg/antireplay"
	"github.com/flynn/hallowgcp/pkg/authorization"
	"github.com/flynn/hallowgcp/pkg/ca"
	"github.com/flynn/hallowgcp/pkg/kmssign"
	"github.com/flynn/hallowgcp/pkg/kmssign/kmssim"
	"github.com/flynn/hallowgcp/pkg/pb"
)

func main() {
	cfg, err := ca.ServerConfigFromEnv()
	if err != nil {
		log.Fatalf("failed to init config: %v", err)
	}

	var kmsClient kmssign.KMSClient
	if cfg.FakeKMS {
		kmsClient = kmssim.NewClient([]string{
			cfg.CAKMSKeyName,
		})
	} else {
		var err error
		kmsClient, err = kms.NewKeyManagementClient(context.Background())
		if err != nil {
			log.Fatalf("error initializing kms client: %s", err)
		}
	}

	caKey, err := kmssign.NewKey(context.Background(), kmsClient, cfg.CAKMSKeyName)
	if err != nil {
		log.Fatalf("error initializing kms key: %v", err)
	}

	caSSHKeyStr, err := caKey.MarshalSSHAuthorizedKey(cfg.CAKMSKeyComment)
	if err != nil {
		log.Fatalf("failed to marshal CA SSH key: %v", err)
	}
	log.Printf("CA SSH public key:\n%s", caSSHKeyStr)

	sshSigner, err := ssh.NewSignerFromSigner(caKey)
	if err != nil {
		log.Fatalf("failed to create ssh signer: %v", err)
	}

	logger, err := zap.NewDevelopment()
	if err != nil {
		panic(err)
	}

	biscuitAuth, err := authorization.NewBiscuitServerInterceptor(
		cfg.HubauthPubKey,
		antireplay.NewChecker(
			antireplay.NewRAMStore(),
			cfg.AntiReplayNonceValidityWindow,
			cfg.AntiReplayNonceMaxAge,
		),
		cfg.AudienceName,
		cfg.AudiencePubKey,
		logger.Named("biscuit-interceptor"),
	)
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(biscuitAuth.Unary),
	)

	pb.RegisterHallowGCPServer(grpcServer, ca.NewServer(
		ca.New(rand.Reader, sshSigner),
		cfg.AllowedKeyTypes,
		cfg.CertValidityDuration,
	))

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("server listening on %s", cfg.ListenAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
