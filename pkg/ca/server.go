package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/status"

	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/hallowgcp/pkg/authorization"
	"github.com/flynn/hallowgcp/pkg/pb"
)

type server struct {
	pb.UnimplementedHallowGCPServer

	ca                   CertificateAuthority
	allowedKeyTypes      map[string]struct{}
	certValidityDuration time.Duration
}

func NewServer(ca CertificateAuthority, allowedKeyTypes map[string]struct{}, certValidityDuration time.Duration) pb.HallowGCPServer {
	return &server{
		ca:                   ca,
		allowedKeyTypes:      allowedKeyTypes,
		certValidityDuration: certValidityDuration,
	}
}

func (s *server) NewCertificate(ctx context.Context, req *pb.NewCertificateRequest) (*pb.NewCertificateResponse, error) {
	userMetas, ok := ctx.Value(authorization.CtxAuthenticatedUserMetasKey).(*signedbiscuit.UserSignatureMetadata)
	if !ok {
		return nil, status.Errorf(403, "invalid authorization")
	}

	publicKey, err := ssh.ParsePublicKey(req.PublicKey)
	if err != nil {
		return nil, status.Errorf(400, "failed to parse public key: %v", err)
	}
	if _, ok := s.allowedKeyTypes[publicKey.Type()]; !ok {
		return nil, status.Errorf(400, "disallowed public key type")
	}
	if err := validatePublicKey(publicKey); err != nil {
		return nil, status.Errorf(400, "failed to validate public key: %v", err)
	}

	serial, err := s.ca.GenerateSerial()
	if err != nil {
		return nil, status.Errorf(500, "failed to generate serial: %v", err)
	}

	template := ssh.Certificate{
		Key:             publicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           userMetas.UserEmail,
		ValidPrincipals: req.Principals,
		ValidAfter:      uint64(time.Now().Add(-time.Minute * 1).Unix()),
		ValidBefore:     uint64(time.Now().Add(s.certValidityDuration).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
				"permit-user-rc":          "",
			},
		},
	}

	sshCert, err := s.ca.Sign(template)
	if err != nil {
		return nil, status.Errorf(500, "failed to sign the certificate: %v", err)
	}

	return &pb.NewCertificateResponse{Certificate: ssh.MarshalAuthorizedKey(sshCert)}, nil
}

func (s *server) CAPublicKey(ctx context.Context, req *pb.CAPublicKeyRequest) (*pb.CAPublicKeyResponse, error) {
	pubkey := s.ca.PublicKey()
	return &pb.CAPublicKeyResponse{
		CaPublicKey: pubkey.Marshal(),
		KeyType:     pubkey.Type(),
	}, nil
}

var errUnknownKeyType = errors.New("hallow: public key is of an unknown type, can't validate")
var errSmallRsaKey = errors.New("hallow: rsa: key size is too small")

func validatePublicKey(sshPubKey ssh.PublicKey) error {
	cryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("hallow: ssh public key is not a CryptoPublicKey")
	}

	switch pubKey := cryptoPubKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		smallestAcceptedSize := 2048
		if pubKey.N.BitLen() < smallestAcceptedSize {
			return errSmallRsaKey
		}
		return nil
	case *ecdsa.PublicKey, ed25519.PublicKey:
		return nil
	default:
		return errUnknownKeyType
	}
}
