package kmssign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"

	gax "github.com/googleapis/gax-go/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/exp/errors/fmt"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

type KMSClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
}

type SignerOpts interface {
	crypto.SignerOpts

	Context() context.Context
}

func NewKey(ctx context.Context, client KMSClient, name string) (*Key, error) {
	res, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return nil, fmt.Errorf("kmssign: error looking up key: %w", err)
	}

	k := &Key{
		name: name,
		c:    client,
	}

	switch res.Algorithm {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		k.hash = crypto.SHA256
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		k.hash = crypto.SHA384
	default:
		return nil, fmt.Errorf("kmssign: algorithm %v is not supported", res.Algorithm)
	}

	keyDER, _ := pem.Decode([]byte(res.Pem))
	if keyDER == nil {
		return nil, fmt.Errorf("kmssign: error decode public key PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(keyDER.Bytes)
	if err != nil {
		return nil, fmt.Errorf("kmssign: error decoding public key DER: %w", err)
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("kmssign: unexpected key type %T", ecdsaKey)
	}
	k.pub = ecdsaKey

	return k, nil
}

func NewPrivateKey(client KMSClient, name string, hash crypto.Hash) *Key {
	return &Key{name: name, hash: hash, c: client}
}

type Key struct {
	name string
	pub  *ecdsa.PublicKey
	hash crypto.Hash
	c    KMSClient
}

func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

func (k *Key) HashFunc() crypto.Hash {
	return k.hash
}

// We need to implement MarshalSSHAuthorizedKey because `ssh.MarshalAuthorizedKey` will
// not include the Comment, since the `ssh.PublicKey` struct doesn't store
// the comment at all. This could be improved by calling ssh.MarshalAuthorizedKey
// and slicing the string, but like, that seems worse than just base64ing it.
func (k *Key) MarshalSSHAuthorizedKey(comment string) (string, error) {
	sshCaPubkey, err := ssh.NewPublicKey(k.Public().(*ecdsa.PublicKey))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"%s %s %s\n",
		sshCaPubkey.Type(),
		base64.StdEncoding.EncodeToString(sshCaPubkey.Marshal()),
		comment,
	), nil
}

func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var ctx context.Context
	if o, ok := opts.(SignerOpts); ok {
		ctx = o.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.HashFunc() != k.hash {
		return nil, fmt.Errorf("kmssign: incorrect hash function %v, required to be %v", opts.HashFunc(), k.hash)
	}

	if g, w := len(digest), k.hash.Size(); g != w {
		return nil, fmt.Errorf("kmssign: invalid digest length, got %d bytes, want %d", g, w)
	}

	req := &kmspb.AsymmetricSignRequest{
		Name: k.name,
	}
	switch k.hash {
	case crypto.SHA256:
		req.Digest = &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}}
	case crypto.SHA384:
		req.Digest = &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}}
	default:
		return nil, fmt.Errorf("kmssign: unsupported hash function %v", k.hash)
	}

	res, err := k.c.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("kmssign: error signing: %w", err)
	}

	return res.Signature, nil
}

func (k *Key) Verify(digest, sig []byte) bool {
	// ecdsa.Verify will panic with a nil public key
	// only happens if Verify is called from a custom created Key
	// or one obtained from NewPrivateKey
	if k.pub == nil {
		panic("kmssign: nil ecdsa public key")
	}
	return ecdsa.VerifyASN1(k.pub, digest, sig)
}
