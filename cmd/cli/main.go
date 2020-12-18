package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/flynn/hallowgcp/pkg/authorization"
	"github.com/flynn/hallowgcp/pkg/ca"
	"github.com/flynn/hallowgcp/pkg/hubauth"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
)

func main() {
	log.SetFlags(0)

	var CAEndpoint, authEndpoint, oauthClientID, localRedirectURI, audienceName, principals string
	flag.StringVar(&authEndpoint, "auth-endpoint", "", "the endpoint handling oauth / biscuit authentication")
	flag.StringVar(&oauthClientID, "client-id", "", "the oauth client ID")
	flag.StringVar(&audienceName, "audience", "", "the oauth audience name")
	flag.StringVar(&CAEndpoint, "ca-endpoint", "localhost:8001", "the CA server endpoint issuing SSH certificates")
	flag.StringVar(&localRedirectURI, "local-redirect", "localhost:8888", "the local address:port to be redirected to during authentication (the port need to be free)")
	flag.StringVar(&principals, "principals", "", "comma separated list of principals added in the certificate")
	flag.Parse()

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s destination:\n", os.Args[0])
		fmt.Printf(`
%s connects and logs into the specified destination,
which may be specified as either [user@]hostname or a URI of the form ssh://[user@]hostname[:port].

`, os.Args[0])
		flag.PrintDefaults()
	}

	if authEndpoint == "" {
		flag.Usage()
		log.Fatal("flag -auth-endpoint is required")
	}
	if oauthClientID == "" {
		flag.Usage()
		log.Fatal("flag -client-id is required")
	}
	if audienceName == "" {
		flag.Usage()
		log.Fatal("flag -audience is required")
	}
	if principals == "" {
		flag.Usage()
		log.Fatal("flag -principals is required")
	}

	if flag.NArg() != 1 {
		flag.Usage()
		log.Fatal("a destination argument is required")
	}
	sshTarget := flag.Arg(0)

	priv, pub, err := ca.GenerateKey(ca.KeyTypeECDSAP256)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	log.Println("generated user key pair")

	hubauthClient := hubauth.NewClient(
		authEndpoint,
		audienceName,
		oauthClientID,
		localRedirectURI, // this address must be an authorized redirect URI on the oauth server.
		pub.(*ecdsa.PublicKey),
	)

	hubauthPubKey, err := hubauthClient.PublicKey()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("retrieved hubauth root pubkey: %s", base64.URLEncoding.EncodeToString(hubauthPubKey))

	log.Println("open the following url in your browser to authenticate:")
	log.Println(hubauthClient.AuthorizeUri())
	token, err := hubauthClient.Login()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("authentication successful, generating SSH certificate...")

	clientInterceptor, err := authorization.NewBiscuitClientInterceptor(hubauthPubKey, priv.(*ecdsa.PrivateKey), token.AccessToken)
	if err != nil {
		log.Fatal(err)
	}

	certClient := ca.NewClient(CAEndpoint,
		grpc.WithInsecure(),
		grpc.WithUnaryInterceptor(clientInterceptor.Unary),
	)

	cert, err := certClient.GenerateCertificate(pub, strings.Split(principals, ","))
	if err != nil {
		log.Fatalf("failed to generate certificate: %v", err)
	}

	log.Println("success generating SSH certificate, opening SSH connection...")

	privKeyBytes, err := x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))
	if err != nil {
		log.Fatalf("failed to marshal priv key: %v", err)
	}

	tmpDir := os.TempDir()
	privPath := filepath.Join(tmpDir, "id")
	pubPath := filepath.Join(tmpDir, "id.pub")
	certPath := filepath.Join(tmpDir, "id-cert.pub")

	err = ioutil.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	}), 0600)
	if err != nil {
		log.Fatal(err)
	}
	// TODO: do we want to remove those file when session end
	// or somehow allow user to reuse it ?
	defer os.Remove(privPath)

	err = ioutil.WriteFile(pubPath, ssh.MarshalAuthorizedKey(cert.Key), 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(pubPath)

	err = ioutil.WriteFile(certPath, ssh.MarshalAuthorizedKey(cert), 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(certPath)

	sshArgs := []string{"ssh", "-i", privPath, sshTarget}

	command := exec.CommandContext(context.Background(), sshArgs[0], sshArgs[1:]...)
	command.Env = os.Environ()
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	if err := command.Run(); err != nil {
		log.Println(err)
	}
}
