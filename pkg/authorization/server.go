package authorization

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/flynn/biscuit-go"
	"github.com/flynn/biscuit-go/cookbook/signedbiscuit"
	"github.com/flynn/biscuit-go/sig"
	"github.com/flynn/hallowgcp/pkg/antireplay"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var ErrNotAuthorized = status.Error(codes.PermissionDenied, "not authorized")

const MetadataAuthorization = "authorization"

type ctxAuthUserMetas string

const CtxAuthenticatedUserMetasKey ctxAuthUserMetas = "userMetas"

type BiscuitServerInterceptor interface {
	Unary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error)
	Stream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error
}

type biscuitServerInterceptor struct {
	logger         *zap.Logger
	pubkey         sig.PublicKey
	antiReplay     antireplay.Checker
	audience       string
	audiencePubKey *ecdsa.PublicKey
}

func NewBiscuitServerInterceptor(rootPubKey sig.PublicKey, antiReplay antireplay.Checker, audience string, audiencePubKey *ecdsa.PublicKey, logger *zap.Logger) (BiscuitServerInterceptor, error) {
	return &biscuitServerInterceptor{
		logger:         logger,
		antiReplay:     antiReplay,
		pubkey:         rootPubKey,
		audience:       audience,
		audiencePubKey: audiencePubKey,
	}, nil
}

func (i *biscuitServerInterceptor) Unary(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	verifier, err := i.newVerifierFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	metas, err := verifier.verify(info.FullMethod, req)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, CtxAuthenticatedUserMetasKey, metas)
	return handler(ctx, req)
}

func (i *biscuitServerInterceptor) Stream(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	verifier, err := i.newVerifierFromCtx(ss.Context())
	if err != nil {
		return err
	}

	_, err = verifier.verify(info.FullMethod, nil)
	if err != nil {
		return err
	}

	// TODO  inject signature metas in context
	// not sure how to set the context on a stream handler ?

	return handler(srv, ss)
}

type grpcVerifier struct {
	ctx            context.Context
	verifier       biscuit.Verifier
	antiReplay     antireplay.Checker
	audience       string
	audiencePubKey *ecdsa.PublicKey
	logger         *zap.Logger
}

func (i *biscuitServerInterceptor) newVerifierFromCtx(ctx context.Context) (*grpcVerifier, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, errors.New("authorization: failed to retrieve context metadata")
	}

	token, ok := md[MetadataAuthorization]
	if !ok {
		return nil, fmt.Errorf("authorization: missing required context metadata %q", MetadataAuthorization)
	}
	tokenBytes, err := base64.URLEncoding.DecodeString(token[0])
	if err != nil {
		return nil, err
	}
	b, err := biscuit.Unmarshal(tokenBytes)
	if err != nil {
		return nil, err
	}

	verifier, err := b.Verify(i.pubkey)
	if err != nil {
		return nil, err
	}

	return &grpcVerifier{
		ctx:            ctx,
		verifier:       verifier,
		logger:         i.logger,
		antiReplay:     i.antiReplay,
		audience:       i.audience,
		audiencePubKey: i.audiencePubKey,
	}, nil
}

// fullMethod must be the full RPC method string, i.e., /package.service/method.
func (v *grpcVerifier) verify(fullMethod string, req interface{}) (*signedbiscuit.UserSignatureMetadata, error) {
	var fields map[biscuit.String]biscuit.Atom

	if req != nil {
		protoMsg, ok := req.(proto.Message)
		if !ok {
			return nil, errors.New("authorization: invalid request")
		}

		fields = v.flattenProtoMessage(protoMsg.ProtoReflect())
	}

	debugFacts := make([]string, 0, len(fields)+1)

	split := strings.Split(fullMethod, "/")
	if len(split) != 3 {
		return nil, errors.New("authorization: failed to split fullMethod")
	}

	// Add request service, method and arguments to the verifier
	serviceFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "service",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String(split[1])},
	}}
	v.verifier.AddFact(serviceFact)
	debugFacts = append(debugFacts, serviceFact.String())

	methodFact := biscuit.Fact{Predicate: biscuit.Predicate{
		Name: "method",
		IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), biscuit.String(split[2])},
	}}
	v.verifier.AddFact(methodFact)
	debugFacts = append(debugFacts, methodFact.String())

	for name, value := range fields {
		argFact := biscuit.Fact{Predicate: biscuit.Predicate{
			Name: "arg",
			IDs:  []biscuit.Atom{biscuit.Symbol("ambient"), name, value},
		}}
		v.verifier.AddFact(argFact)
		debugFacts = append(debugFacts, argFact.String())
	}
	v.logger.Debug("flattened proto request", zap.Strings("facts", debugFacts))

	var signatureMetas *signedbiscuit.UserSignatureMetadata
	var err error
	v.verifier, signatureMetas, err = signedbiscuit.WithSignatureVerification(v.verifier, v.audience, v.audiencePubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature: %w", err)
	}

	if err := v.verifier.Verify(); err != nil {
		v.logger.Warn("failed to verify biscuit",
			zap.Error(err),
			zap.String("world", v.verifier.PrintWorld()),
			zap.Strings("ambient-facts", debugFacts),
		)
		return nil, ErrNotAuthorized
	}

	v.logger.Info(
		"success verifying signed biscuit",
		zap.String("userID", signatureMetas.UserID),
		zap.String("userEmail", signatureMetas.UserEmail),
		zap.String("issueTime", signatureMetas.IssueTime.String()),
		zap.String("signatureTimestamp", signatureMetas.UserSignatureTimestamp.String()),
		zap.Binary("signatureNonce", signatureMetas.UserSignatureNonce),
	)

	// Anti replay verifications using signatureMetas
	if err := v.antiReplay.Check(antireplay.Nonce{
		ID:        signatureMetas.UserEmail,
		Value:     signatureMetas.UserSignatureNonce,
		CreatedAt: signatureMetas.UserSignatureTimestamp,
	}); err != nil {
		return nil, err
	}

	return signatureMetas, nil
}

func (v *grpcVerifier) flattenProtoMessage(msg protoreflect.Message) map[biscuit.String]biscuit.Atom {
	out := make(flattenedMessage)

	fields := msg.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)

		var elts map[interface{}]protoreflect.Value
		var fieldName func(key interface{}) string

		switch {
		case field.IsMap():
			m := msg.Get(field).Map()
			elts = make(map[interface{}]protoreflect.Value, m.Len())
			m.Range(func(mk protoreflect.MapKey, value protoreflect.Value) bool {
				elts[mk.Interface()] = value
				return true
			})
			fieldName = func(key interface{}) string {
				return fmt.Sprintf("%s.%v", field.Name(), key)
			}
		default:
			elts = map[interface{}]protoreflect.Value{struct{}{}: msg.Get(field)}
			fieldName = func(key interface{}) string {
				return string(field.Name())
			}
		}

		for key, elt := range elts {
			switch field.Kind() {
			case protoreflect.BoolKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					if e.Bool() {
						out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(1))
					} else {
						out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(0))
					}
				})
			case protoreflect.EnumKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					// swap the enum value to its name from the definition and use it as a string on biscuit side
					out.Insert(biscuit.String(fieldName(key)), biscuit.String(field.Enum().Values().ByNumber(e.Enum()).Name()))
				})
			case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(e.Int()))
				})
			case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(e.Uint()))
				})
			case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(e.Int()))
				})
			case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					if e.Uint() > math.MaxInt64 {
						v.logger.Warn("uint64 field does not fit in int64", zap.String("field", fieldName(key)))
						return
					}
					out.Insert(biscuit.String(fieldName(key)), biscuit.Integer(e.Uint()))
				})
			case protoreflect.StringKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.String(e.String()))
				})
			case protoreflect.BytesKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					out.Insert(biscuit.String(fieldName(key)), biscuit.Bytes(e.Bytes()))
				})
			case protoreflect.MessageKind:
				valuesIterator(field, elt, func(e protoreflect.Value) {
					switch e.Message().Descriptor().FullName() {
					case "google.protobuf.Timestamp":
						ts := e.Message().Interface().(*timestamppb.Timestamp)
						out.Insert(biscuit.String(fieldName(key)), biscuit.Date(ts.AsTime()))
					default:
						// recurse until we only get basic types concatenating sub field name with parent field name
						subout := v.flattenProtoMessage(e.Message())
						for k, value := range subout {
							name := fmt.Sprintf("%s.%s", fieldName(key), string(k))
							out.Insert(biscuit.String(name), value)
						}
					}
				})
			default:
				// Float, Double, Group...
				v.logger.Warn("unsupported proto kind",
					zap.String("field", fieldName(key)),
					zap.String("kind", field.Kind().String()),
				)
			}
		}
	}

	return out
}

type flattenedMessage map[biscuit.String]biscuit.Atom

// Insert add the value to the map, at key index. If a value with this key already exists, it will create a
// biscuit.List and add the original and new values to it. Other inserts at this key will keep appending to the list.
// When the key doesn't exists, the original value is stored in the map.
func (f flattenedMessage) Insert(key biscuit.String, value biscuit.Atom) {
	if v, keyExists := f[key]; keyExists {
		if l, isSet := v.(biscuit.Set); isSet {
			f[key] = append(l, value)
		} else {
			f[key] = biscuit.Set{v, value}
		}

		return
	}

	f[key] = value
}

// valuesIterator calls cb for every field values (once for regular types, N for repeated types)
func valuesIterator(field protoreflect.FieldDescriptor, element protoreflect.Value, cb func(e protoreflect.Value)) {
	if field.IsList() {
		list := element.List()
		for i := 0; i < list.Len(); i++ {
			cb(list.Get(i))
		}
		return
	}

	cb(element)
}
