package antireplay

import (
	"time"
)

type Nonce struct {
	ID        string
	Value     []byte
	CreatedAt time.Time
}

type Store interface {
	Insert(nonce Nonce) error
	Get(ID string) ([]Nonce, error)
}

type ramStore struct {
	store []Nonce
}

func NewRAMStore() Store {
	return &ramStore{}
}

func (s *ramStore) Insert(nonce Nonce) error {
	s.store = append(s.store, nonce)
	return nil
}

func (s *ramStore) Get(id string) ([]Nonce, error) {
	var userNonces []Nonce
	for _, n := range s.store {
		if n.ID == id {
			userNonces = append(userNonces, n)
		}
	}
	return userNonces, nil
}
