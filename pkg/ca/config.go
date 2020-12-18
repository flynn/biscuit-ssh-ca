package ca

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/flynn/biscuit-go/sig"
	"golang.org/x/crypto/ssh"
)

var (
	defaultListenAddr                    = ":8001"
	defaultAntiReplayNonceValidityWindow = 5 * time.Second
	defaultAntiReplayNonceMaxAge         = 60 * time.Minute
	defaultCertValidityDuration          = 30 * time.Minute
	defaultAllowedKeyTypes               = map[string]struct{}{
		ssh.KeyAlgoED25519:    {},
		ssh.KeyAlgoECDSA521:   {},
		ssh.KeyAlgoECDSA384:   {},
		ssh.KeyAlgoECDSA256:   {},
		ssh.KeyAlgoSKED25519:  {},
		ssh.KeyAlgoSKECDSA256: {},
	}
	defaultCAKMSKeyComment = "ca@hallowgpc"
)

type Config struct {
	HubauthPubKey sig.PublicKey

	CAKMSKeyName    string
	CAKMSKeyComment string

	AudienceName   string
	AudiencePubKey *ecdsa.PublicKey

	AllowedKeyTypes      map[string]struct{}
	CertValidityDuration time.Duration

	ListenAddr string

	AntiReplayNonceMaxAge         time.Duration
	AntiReplayNonceValidityWindow time.Duration

	FakeKMS bool
}

// ServerConfigFromEnv creates a config initialized with default values, and overrided
// by provided env variables, from the list below:
// - ALLOWED_KEY_TYPES:        comma separated strings on allowed key types for certificate generation, from golang.org/x/crypto/ssh.KeyAlg*.
// - CERT_VALIDITY_DURATION:   duration where the SSH certificate will be valid.
// - LISTEN_ADDR:              host:port string where the CA server will be listening for connections.
// - ANTIREPLAY_NONCE_WINDOW:  duration window around the current server time where the nonce creation date is considered acceptable.
//                             nonces created before or after this grace period will be rejected.
// - ANTIREPLAY_NONCE_MAX_AGE: period of time where nonce are kept in storage, preventing them to be replayed.
// - HUBAUTH_PUBLIC_KEY:       required. the public key used to validate biscuits.
// - AUDIENCE_NAME:            required. the name of the audience, used for validating biscuit audience signature.
// - AUDIENCE_PUBLIC_KEY:      required. the audience public key, used for validating biscuit audience signature.
// - CA_KMS_KEY_NAME:          required. the KMS key name used by the CA to sign SSH certificates.
// - CA_KMS_KEY_COMMENT:       a comment appended to the CA SSH public key
// - FAKE_KMS:                 use a fake KMS (for local development)
func ServerConfigFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:                    defaultListenAddr,
		AllowedKeyTypes:               defaultAllowedKeyTypes,
		CertValidityDuration:          defaultCertValidityDuration,
		AntiReplayNonceMaxAge:         defaultAntiReplayNonceMaxAge,
		AntiReplayNonceValidityWindow: defaultAntiReplayNonceValidityWindow,
		CAKMSKeyComment:               defaultCAKMSKeyComment,
	}

	allowedKeyTypesStr := os.Getenv("ALLOWED_KEY_TYPES")
	if allowedKeyTypesStr != "" {
		keyTypes := strings.Split(allowedKeyTypesStr, " ")
		cfg.AllowedKeyTypes = make(map[string]struct{}, len(keyTypes))
		for _, kt := range keyTypes {
			cfg.AllowedKeyTypes[kt] = struct{}{}
		}
	}

	certValidityDurationStr := os.Getenv("CERT_VALIDITY_DURATION")
	if certValidityDurationStr != "" {
		var err error
		cfg.CertValidityDuration, err = time.ParseDuration(certValidityDurationStr)
		if err != nil {
			return nil, fmt.Errorf("config: failed to parse CERT_VALIDITY_DURATION: %v", err)
		}
	}

	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr != "" {
		cfg.ListenAddr = listenAddr
	}

	nonceWindow := os.Getenv("ANTIREPLAY_NONCE_WINDOW")
	if nonceWindow != "" {
		var err error
		cfg.AntiReplayNonceValidityWindow, err = time.ParseDuration(nonceWindow)
		if err != nil {
			return nil, fmt.Errorf("config: failed to parse ANTIREPLAY_NONCE_WINDOW: %v", err)
		}
	}
	nonceDuration := os.Getenv("ANTIREPLAY_NONCE_MAX_AGE")
	if nonceDuration != "" {
		var err error
		cfg.AntiReplayNonceMaxAge, err = time.ParseDuration(nonceDuration)
		if err != nil {
			return nil, fmt.Errorf("config: failed to parse ANTIREPLAY_NONCE_DURATION: %v", err)
		}
	}

	hubauthPubkey := os.Getenv("HUBAUTH_PUBLIC_KEY")
	if hubauthPubkey == "" {
		return nil, errors.New("config: HUBAUTH_PUBLIC_KEY env is required")
	}
	pubKey, err := base64.StdEncoding.DecodeString(hubauthPubkey)
	if err != nil {
		return nil, fmt.Errorf("config: failed to base64 decode HUBAUTH_PUBLIC_KEY: %v", err)
	}
	cfg.HubauthPubKey, err = sig.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("config: failed to create hubauth biscuit sig.PublicKey: %v", err)
	}

	cfg.AudienceName = os.Getenv("AUDIENCE_NAME")
	if cfg.AudienceName == "" {
		return nil, errors.New("config: AUDIENCE_NAME is required")
	}

	audiencePubKey := os.Getenv("AUDIENCE_PUBLIC_KEY")
	if audiencePubKey == "" {
		return nil, errors.New("config: AUDIENCE_PUBLIC_KEY is required")
	}

	audienceKeyBytes, err := base64.StdEncoding.DecodeString(audiencePubKey)
	if err != nil {
		return nil, fmt.Errorf("config: failed to base64 decode AUDIENCE_PUBLIC_KEY: %v", err)
	}
	audienceECPubKey, err := x509.ParsePKIXPublicKey(audienceKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("config: failed to parse audience PKIX public key: %v", err)
	}
	var ok bool
	cfg.AudiencePubKey, ok = audienceECPubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("config: invalid audience public key type, got %T, want *ecdsa.PublicKey", audienceECPubKey)
	}

	cfg.CAKMSKeyName = os.Getenv("CA_KMS_KEY_NAME")
	if cfg.CAKMSKeyName == "" {
		return nil, fmt.Errorf("config: CA_KMS_KEY_NAME is required")
	}

	CAKeyComment := os.Getenv("CA_KMS_KEY_COMMENT")
	if CAKeyComment != "" {
		cfg.CAKMSKeyComment = CAKeyComment
	}

	if os.Getenv("FAKE_KMS") != "" {
		cfg.FakeKMS = true
	}

	return cfg, nil
}
