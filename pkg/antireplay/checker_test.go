package antireplay

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheck(t *testing.T) {
	nonceWindow := time.Second
	nonceMaxAge := time.Minute

	now := time.Now()

	testCases := []struct {
		Desc         string
		StoredNonces []Nonce
		CheckedNonce Nonce
		ExpectedErr  error
	}{
		{
			Desc: "valid nonce",
			CheckedNonce: Nonce{
				ID:        "id1",
				CreatedAt: now,
				Value:     []byte{1},
			},
			ExpectedErr: nil,
		},
		{
			Desc: "same id different value",
			StoredNonces: []Nonce{
				{
					ID:        "id1",
					CreatedAt: now,
					Value:     []byte{1},
				},
			},
			CheckedNonce: Nonce{
				ID:        "id1",
				CreatedAt: now,
				Value:     []byte{2},
			},
			ExpectedErr: nil,
		},
		{
			Desc: "same value different id",
			StoredNonces: []Nonce{
				{
					ID:        "id1",
					CreatedAt: now,
					Value:     []byte{1},
				},
			},
			CheckedNonce: Nonce{
				ID:        "id2",
				CreatedAt: now,
				Value:     []byte{1},
			},
			ExpectedErr: nil,
		},
		{
			Desc: "replay",
			StoredNonces: []Nonce{
				{
					ID:        "id1",
					CreatedAt: now.Add(nonceMaxAge / 2),
					Value:     []byte{1},
				},
			},
			CheckedNonce: Nonce{
				ID:        "id1",
				CreatedAt: now,
				Value:     []byte{1},
			},
			ExpectedErr: ErrReplay,
		},
		{
			Desc: "too old",
			CheckedNonce: Nonce{
				ID:        "id1",
				CreatedAt: now.Add(-nonceWindow),
				Value:     []byte{1},
			},
			ExpectedErr: ErrNonceOOB,
		},
		{
			Desc: "in the future",
			CheckedNonce: Nonce{
				ID:        "id1",
				CreatedAt: now.Add(nonceWindow + time.Millisecond),
				Value:     []byte{1},
			},
			ExpectedErr: ErrNonceOOB,
		},
		{
			Desc: "too old stored nonces are ignored",
			StoredNonces: []Nonce{
				{
					ID:        "id1",
					CreatedAt: now.Add(-nonceMaxAge),
					Value:     []byte{1},
				},
			},
			CheckedNonce: Nonce{
				ID:        "id1",
				CreatedAt: now,
				Value:     []byte{1},
			},
			ExpectedErr: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Desc, func(t *testing.T) {
			store := NewRAMStore()
			for _, sn := range testCase.StoredNonces {
				require.NoError(t, store.Insert(sn))
			}

			checker := NewChecker(store, nonceWindow, nonceMaxAge)
			err := checker.Check(testCase.CheckedNonce)
			require.Equal(t, testCase.ExpectedErr, err)
		})
	}
}
