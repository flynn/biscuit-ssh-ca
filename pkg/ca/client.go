package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/flynn/hallowgcp/pkg/pb"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

type KeyType uint8

const (
	KeyTypeECDSAP256 KeyType = iota
	KeyTypeECDSAP384
	KeyTypeECDSAP521
	KeyTypeED25519
	KeyTypeRSA2048
	KeyTypeRSA4096
)

type Client interface {
	GenerateCertificate(pubkey crypto.PublicKey, principals []string) (*ssh.Certificate, error)
}

type client struct {
	grpcEndpoint string
	grpcOpts     []grpc.DialOption
}

func NewClient(caEndpoint string, opts ...grpc.DialOption) Client {
	return &client{
		grpcEndpoint: caEndpoint,
		grpcOpts:     opts,
	}
}

func (c *client) GenerateCertificate(pubkey crypto.PublicKey, principals []string) (*ssh.Certificate, error) {
	conn, err := grpc.Dial(c.grpcEndpoint, c.grpcOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to CA server: %v", err)
	}
	defer conn.Close()
	caClient := pb.NewHallowGCPClient(conn)

	sshPubKey, err := ssh.NewPublicKey(pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh key: %v", err)
	}

	resp, err := caClient.NewCertificate(context.Background(), &pb.NewCertificateRequest{
		PublicKey:  sshPubKey.Marshal(),
		Principals: principals,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate new certificate: %v", err)
	}

	sshCert, _, _, _, err := ssh.ParseAuthorizedKey(resp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cert: %v", err)
	}

	return sshCert.(*ssh.Certificate), nil
}

func GenerateKey(keyType KeyType) (crypto.Signer, crypto.PublicKey, error) {
	switch keyType {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521:
		var curve elliptic.Curve
		switch keyType {
		case KeyTypeECDSAP256:
			curve = elliptic.P256()
		case KeyTypeECDSAP384:
			curve = elliptic.P384()
		case KeyTypeECDSAP521:
			curve = elliptic.P521()
		}
		privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return privKey, privKey.Public(), nil
	case KeyTypeRSA2048, KeyTypeRSA4096:
		var size int = 0
		switch keyType {
		case KeyTypeRSA2048:
			size = 2048
		case KeyTypeRSA4096:
			size = 4096
		}
		privKey, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return nil, nil, err
		}
		return privKey, privKey.Public(), nil
	case KeyTypeED25519:
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		return privKey, pubKey, err
	default:
		return nil, nil, fmt.Errorf("client: unknown key type: %x", keyType)
	}
}
