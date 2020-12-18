package ca

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/ssh"
)

type CertificateAuthority interface {
	Sign(template ssh.Certificate) (*ssh.Certificate, error)
	PublicKey() ssh.PublicKey
	GenerateSerial() (uint64, error)
}

type ca struct {
	rng    io.Reader
	signer ssh.Signer
}

var _ CertificateAuthority = (*ca)(nil)

func New(rng io.Reader, signer ssh.Signer) CertificateAuthority {
	return &ca{
		rng:    rng,
		signer: signer,
	}
}

func (c *ca) PublicKey() ssh.PublicKey {
	return c.signer.PublicKey()
}

func (c *ca) Sign(template ssh.Certificate) (*ssh.Certificate, error) {
	cert := &ssh.Certificate{
		Key:             template.Key,
		Serial:          template.Serial,
		CertType:        template.CertType,
		KeyId:           template.KeyId,
		ValidPrincipals: template.ValidPrincipals,
		ValidAfter:      template.ValidAfter,
		ValidBefore:     template.ValidBefore,
		SignatureKey:    c.signer.PublicKey(),
		Permissions: ssh.Permissions{
			CriticalOptions: template.CriticalOptions,
			Extensions:      template.Extensions,
		},
	}

	err := cert.SignCert(c.rng, c.signer)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *ca) GenerateSerial() (uint64, error) {
	var b [8]byte
	_, err := c.rng.Read(b[:])
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}
