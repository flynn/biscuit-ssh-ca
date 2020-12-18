package authorization

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"

	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/biscuit-go/sig"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type BiscuitClientInterceptor interface {
	Unary(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error
	Stream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error)
}

type biscuitClientInterceptor struct {
	rootPublicKey sig.PublicKey
	userKeyPair   *signedbiscuit.UserKeyPair
	baseToken     []byte
}

func NewBiscuitClientInterceptor(rootPubBytes []byte, userPrivKey *ecdsa.PrivateKey, baseToken string) (BiscuitClientInterceptor, error) {
	rootPubKey, err := sig.NewPublicKey(rootPubBytes)
	if err != nil {
		return nil, err
	}

	userKeypair, err := signedbiscuit.NewECDSAKeyPair(userPrivKey)
	if err != nil {
		return nil, err
	}

	decToken, err := base64.URLEncoding.DecodeString(baseToken)
	if err != nil {
		return nil, err
	}

	return &biscuitClientInterceptor{
		rootPublicKey: rootPubKey,
		userKeyPair:   userKeypair,
		baseToken:     decToken,
	}, nil
}

func (i *biscuitClientInterceptor) Unary(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	authorizedCtx, err := i.signToken(ctx)
	if err != nil {
		return err
	}
	return invoker(authorizedCtx, method, req, reply, cc, opts...)
}

func (i *biscuitClientInterceptor) Stream(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	authorizedCtx, err := i.signToken(ctx)
	if err != nil {
		return nil, err
	}
	return streamer(authorizedCtx, desc, cc, method, opts...)
}

func (i *biscuitClientInterceptor) signToken(ctx context.Context) (context.Context, error) {
	signedToken, err := signedbiscuit.Sign(i.baseToken, i.rootPublicKey, i.userKeyPair)
	if err != nil {
		return nil, err
	}

	md := metadata.Pairs("authorization", base64.URLEncoding.EncodeToString(signedToken))
	return metadata.NewOutgoingContext(ctx, md), nil
}
