package hubauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Token struct {
	RefreshToken          string
	AccessToken           string
	Type                  string
	ExpiresAt             time.Time
	RefreshTokenExpiresAt time.Time
}

func (t Token) String() string {
	s, _ := json.Marshal(t)
	return string(s)
}

type Client struct {
	HTTPClient       *http.Client
	HubauthAddr      string
	audience         string
	addr             string
	clientID         string
	challenge        string
	state            string
	nonce            string
	userPubkey       *ecdsa.PublicKey
	codeResponseChan chan *codeResponse
}

func NewClient(endpoint string, audience string, clientID string, addr string, userPubkey *ecdsa.PublicKey) *Client {
	return &Client{
		HTTPClient:       http.DefaultClient,
		addr:             addr,
		HubauthAddr:      endpoint,
		audience:         audience,
		clientID:         clientID,
		userPubkey:       userPubkey,
		codeResponseChan: make(chan *codeResponse),
	}
}

func (s *Client) Login() (*Token, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatalf("failed to get random nonce: %v", err)
	}
	s.nonce = base64.URLEncoding.EncodeToString(nonce)

	handler := http.NewServeMux()
	handler.HandleFunc("/authorize", s.authorize)
	handler.HandleFunc("/code", s.code)

	srv := &http.Server{
		Addr:    s.addr,
		Handler: handler,
	}
	defer srv.Close()

	go func() {
		if err := srv.ListenAndServe(); err != nil {
			if err != http.ErrServerClosed {
				log.Fatalf("failed to listen and serve: %v", err)
			}
		}
	}()

	select {
	case <-time.After(30 * time.Second):
		return nil, errors.New("timeout")
	case codeResp := <-s.codeResponseChan:
		if codeResp.Nonce != s.nonce {
			return nil, fmt.Errorf("nonce mismatch (%s != %s)", codeResp.Nonce, s.nonce)
		}

		return &Token{
			AccessToken:           codeResp.AccessToken,
			RefreshToken:          codeResp.RefreshToken,
			ExpiresAt:             time.Now().Add(time.Duration(codeResp.ExpiresIn) * time.Second),
			RefreshTokenExpiresAt: time.Now().Add(time.Duration(codeResp.RefreshTokenExpiresIn) * time.Second),
			Type:                  codeResp.TokenType,
		}, nil
	}
}

func (s *Client) PublicKey() ([]byte, error) {
	resp, err := s.HTTPClient.Get(s.HubauthAddr + "/public-key")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	key := &struct {
		PublicKey []byte `json:"public-key"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(key); err != nil {
		return nil, err
	}

	return key.PublicKey, nil
}

func (s *Client) AuthorizeUri() string {
	return fmt.Sprintf("http://%s/authorize", s.addr)
}

func (s *Client) redirectURI() string {
	return fmt.Sprintf("http://%s/code", s.addr)
}

func (s *Client) authorize(w http.ResponseWriter, r *http.Request) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		log.Fatalf("failed to get random challenge: %v", err)
	}
	s.challenge = base64.URLEncoding.EncodeToString(challenge)
	challengeHash := sha256.Sum256([]byte(s.challenge))

	state := make([]byte, 32)
	if _, err := rand.Read(state); err != nil {
		log.Fatalf("failed to get random state: %v", err)
	}
	s.state = base64.URLEncoding.EncodeToString(state)

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/authorize", s.HubauthAddr), nil)
	if err != nil {
		log.Fatalf("failed to create request: %v", err)
	}
	q := req.URL.Query()
	q.Add("code_challenge_method", "S256")
	q.Add("code_challenge", strings.TrimRight(base64.URLEncoding.EncodeToString(challengeHash[:]), "="))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("state", s.state)
	q.Add("nonce", s.nonce)
	q.Add("client_id", s.clientID)
	q.Add("redirect_uri", s.redirectURI())
	req.URL.RawQuery = q.Encode()

	http.Redirect(w, r, req.URL.String(), http.StatusFound)
}

func (s *Client) code(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != s.state {
		log.Fatalf("state mismatch")
	}

	mpubkey, err := x509.MarshalPKIXPublicKey(s.userPubkey)
	if err != nil {
		log.Fatalf("failed to marshal pubkey: %v", err)
	}

	params := url.Values{
		"audience":        []string{s.audience},
		"client_id":       []string{s.clientID},
		"grant_type":      []string{"authorization_code"},
		"redirect_uri":    []string{s.redirectURI()},
		"code":            []string{r.URL.Query().Get("code")},
		"code_verifier":   []string{s.challenge},
		"user_public_key": []string{base64.URLEncoding.EncodeToString(mpubkey)},
	}

	resp, err := s.HTTPClient.PostForm(fmt.Sprintf("%s/token", s.HubauthAddr), params)
	if err != nil {
		log.Fatalf("failed to POST /token: %v", err)
		return
	}

	dec := json.NewDecoder(resp.Body)
	if resp.StatusCode != http.StatusOK {
		e := &errorResponse{}
		if err := dec.Decode(e); err != nil {
			log.Fatalf("failed to decode error response: %v", err)
		}
		log.Fatalf("exchange code failed: %s (%s)", e.Error, e.ErrorDescription)
	}

	d := &codeResponse{}
	if err := dec.Decode(d); err != nil {
		log.Fatalf("failed to decode response: %v", err)
	}

	s.codeResponseChan <- d

	_, _ = w.Write([]byte("Authentication ok, you can close this window"))
}

type codeResponse struct {
	RefreshToken          string `json:"refresh_token"`
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	Nonce                 string `json:"nonce"`
	Audience              string `json:"audience"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
}

type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
