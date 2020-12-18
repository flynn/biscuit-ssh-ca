package authorization

//go:generate ../../build/protoc/bin/protoc  --go_out=testing/ --proto_path ../../build/protoc/include --proto_path testing testing/test.proto

import (
	"crypto/rand"
	"math"
	"testing"
	"time"

	"github.com/flynn/biscuit-go"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	prototesting "github.com/flynn/hallowgcp/pkg/authorization/testing"
)

func TestFlattenedMessageInsert(t *testing.T) {
	f := flattenedMessage{}

	f.Insert("a", biscuit.String("a"))
	f.Insert("b", biscuit.String("b"))
	f.Insert("c", biscuit.Set{biscuit.Integer(0), biscuit.Integer(1)})

	require.Equal(t, flattenedMessage{
		"a": biscuit.String("a"),
		"b": biscuit.String("b"),
		"c": biscuit.Set{biscuit.Integer(0), biscuit.Integer(1)},
	}, f)

	f.Insert("a", biscuit.String("a2"))
	f.Insert("c", biscuit.Integer(2))

	require.Equal(t, flattenedMessage{
		"a": biscuit.Set{biscuit.String("a"), biscuit.String("a2")},
		"b": biscuit.String("b"),
		"c": biscuit.Set{biscuit.Integer(0), biscuit.Integer(1), biscuit.Integer(2)},
	}, f)
}

func TestGrpcVerifierFlattenProtoMessage(t *testing.T) {
	now := timestamppb.New(time.Now()).AsTime()

	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)

	msg := prototesting.Dummy{
		Enum:          prototesting.Enum_V1,
		MapBoolObject: map[bool]*prototesting.Object{true: {Name: "bool1", Value: 1}, false: {Name: "bool2", Value: 2}},
		MapIntObject:  map[int64]*prototesting.Object{41: {Name: "int1", Value: 1}, 42: {Name: "int2", Value: 2}},
		MapStrObject:  map[string]*prototesting.Object{"a": {Name: "str1", Value: 1}, "b": {Name: "str2", Value: 2}},
		RepeatedObjects: []*prototesting.Object{
			{Name: "obj1", Value: 11},
			{Name: "obj2", Value: 12},
			{Name: "obj3", Value: 13},
		},
		SingleObject: &prototesting.Object{Name: "single1", Value: 12},
		BooleanTrue:  true,
		BooleanFalse: false,
		RepeatedStr:  []string{"a", "b", "c"},
		Timestamp:    timestamppb.New(now),
		Bytes:        b,
		Uint32:       5,
		Uint64:       6,
		Sint32:       32,
		// unsupported types should just get skipped:
		Float:    3.14,
		Double:   3.14,
		Overflow: math.MaxInt64 + 1,
	}

	v := &grpcVerifier{
		logger: zap.NewNop(),
	}

	out := v.flattenProtoMessage(msg.ProtoReflect())
	expected := map[biscuit.String]biscuit.Atom{
		"boolean_true":                biscuit.Integer(1),
		"boolean_false":               biscuit.Integer(0),
		"enum":                        biscuit.String("V1"),
		"map_str_object.b.name":       biscuit.String("str2"),
		"map_int_object.41.value":     biscuit.Integer(1),
		"repeated_objects.value":      biscuit.Set{biscuit.Integer(11), biscuit.Integer(12), biscuit.Integer(13)},
		"map_str_object.b.value":      biscuit.Integer(2),
		"map_bool_object.false.value": biscuit.Integer(2),
		"single_object.name":          biscuit.String("single1"),
		"single_object.value":         biscuit.Integer(12),
		"timestamp":                   biscuit.Date(now),
		"map_str_object.a.name":       biscuit.String("str1"),
		"map_str_object.a.value":      biscuit.Integer(1),
		"map_int_object.41.name":      biscuit.String("int1"),
		"map_bool_object.true.value":  biscuit.Integer(1),
		"repeated_objects.name":       biscuit.Set{biscuit.String("obj1"), biscuit.String("obj2"), biscuit.String("obj3")},
		"repeated_str":                biscuit.Set{biscuit.String("a"), biscuit.String("b"), biscuit.String("c")},
		"map_int_object.42.name":      biscuit.String("int2"),
		"map_int_object.42.value":     biscuit.Integer(2),
		"map_bool_object.true.name":   biscuit.String("bool1"),
		"map_bool_object.false.name":  biscuit.String("bool2"),
		"uint32":                      biscuit.Integer(5),
		"uint64":                      biscuit.Integer(6),
		"bytes":                       biscuit.Bytes(b),
		"sint32":                      biscuit.Integer(32),
	}

	require.Equal(t, expected, out)
}
