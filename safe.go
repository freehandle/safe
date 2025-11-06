package safe

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/freehandle/breeze/consensus/messages"
	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/breeze/socket"
	"github.com/freehandle/breeze/util"
	"github.com/freehandle/handles/attorney"
)

type Sender interface {
	Send([]byte) error
}

type SimpleBlockProvider struct {
	Path     string
	Name     string
	Interval time.Duration
}

type GatewayConfig struct {
	Gateway     socket.TokenAddr
	Providers   []socket.TokenAddr
	Credentials crypto.PrivateKey
	Simple      *SimpleBlockProvider
}

type SafeConfig struct {
	Credentials crypto.PrivateKey
	Path        string
	HtmlPath    string
	Port        int
	RestAPIPort int
	ServerName  string
}

type Safe struct {
	vault      *Vault
	actions    *SafeDatabase
	epoch      uint64
	gateway    Sender
	users      map[string]*User
	Session    *util.CookieStore
	templates  *template.Template
	serverName string
	pending    map[string]*attorney.GrantPowerOfAttorney
}

func (s *Safe) CreateSession(handle string) string {
	user, ok := s.users[handle]
	if !ok {
		return ""
	}
	token := user.Token
	seed := make([]byte, 32)
	if n, err := rand.Read(seed); n != 32 || err != nil {
		log.Printf("unexpected error in cookie generation:%v", err)
		return ""
	}
	cookie := hex.EncodeToString(seed)
	s.Session.Set(token, cookie, s.epoch)
	return cookie
}

func (s *Safe) Email(handle string) string {
	return s.vault.HandleToEmail(handle)
}

func (s *Safe) EmailAndToken(handle string) (string, crypto.Token) {
	return s.vault.HandleToEmailAndToken(handle)
}

func (s *Safe) CheckCredentials(handle, password string) bool {
	return s.vault.Check(handle, password)
}

func (s *Safe) Handle(r *http.Request) string {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	if token, ok := s.Session.Get(cookie.Value); ok {
		for handle, user := range s.users {
			if user.Token.Equal(token) {
				return handle
			}
		}
	}
	return ""
}

func (s *Safe) IncorporateGrant(grant *attorney.GrantPowerOfAttorney) {
	for _, user := range s.users {
		if user.Token.Equal(grant.Author) {
			user.GrantPower(grant)
			return
		}
	}
}

func (s *Safe) IncorporateRevoke(revoke *attorney.RevokePowerOfAttorney) {
	for _, user := range s.users {
		if user.Token.Equal(revoke.Author) {
			user.RevokePower(revoke)
			return
		}
	}
}

func (s *Safe) IncorporateJoin(join *attorney.JoinNetwork) {
	for _, user := range s.users {
		if user.Token.Equal(join.Author) {
			user.Confirmed = true
			return
		}
	}
}

func (s *Safe) Send(data []byte) bool {
	if s.gateway == nil {
		log.Print("no connection to send on")
		return false
	}
	data = append([]byte{messages.MsgAction}, data...)
	// dress breeze payment
	util.PutToken(s.vault.Token(), &data)
	util.PutUint64(0, &data)
	signature := s.vault.Secret().Sign(data[1:])
	util.PutSignature(signature, &data)
	err := s.gateway.Send(data[1:]) // gambiarra para converser com o local do simple
	if err != nil {
		log.Printf("connection error: %v\n", err)
		return false
	}
	return true
}

func (s *Safe) GrantAction(handle, grantee string) *attorney.GrantPowerOfAttorney {
	user, ok := s.vault.handle[handle]
	if !ok {
		return nil
	}
	var token crypto.Token
	attorneyBytes, _ := hex.DecodeString(grantee)
	if len(attorneyBytes) != crypto.TokenSize {
		return nil
	}
	copy(token[:], attorneyBytes)
	fingerprint := crypto.EncodeHash(crypto.HashToken(token))
	grant := attorney.GrantPowerOfAttorney{
		Epoch:       s.epoch,
		Author:      user.Secret.PublicKey(),
		Attorney:    token,
		Fingerprint: []byte(fingerprint),
	}
	grant.Sign(user.Secret)
	return &grant
}

func (s *Safe) GrantPower(handle, grantee, fingerprint string) error {
	user, ok := s.vault.handle[handle]
	if !ok {
		return errors.New("invalid user")
	}
	var token crypto.Token
	attorneyBytes, _ := hex.DecodeString(grantee)
	if len(attorneyBytes) != crypto.TokenSize {
		return errors.New("invalid attorney")
	}
	copy(token[:], attorneyBytes)
	grant := attorney.GrantPowerOfAttorney{
		Epoch:       s.epoch,
		Author:      user.Secret.PublicKey(),
		Attorney:    token,
		Fingerprint: []byte(fingerprint),
	}
	grant.Sign(user.Secret)
	data := grant.Serialize()
	s.Send(data)
	return nil
}

func (s *Safe) RevokePower(handle, grantee string) error {
	user, ok := s.vault.handle[handle]
	if !ok {
		return errors.New("invalid user")
	}
	var token crypto.Token
	attorneyBytes, _ := hex.DecodeString(grantee)
	if len(attorneyBytes) != crypto.TokenSize {
		return errors.New("invalid attorney")
	}
	copy(token[:], attorneyBytes)
	grant := attorney.RevokePowerOfAttorney{
		Epoch:    s.epoch,
		Author:   user.Secret.PublicKey(),
		Attorney: token,
	}
	grant.Sign(user.Secret)
	data := grant.Serialize()
	s.Send(data)
	return nil
}

func (s *Safe) SigninWithToken(handle, password, email string) (bool, crypto.Token) {
	token, err := s.vault.NewUser(handle, password, email)
	if err != nil {
		return false, crypto.ZeroToken
	}
	s.users[handle] = &User{token, make([]crypto.Token, 0), false}
	join := attorney.JoinNetwork{
		Epoch:   s.epoch,
		Author:  token,
		Handle:  handle,
		Details: "",
	}
	secret := s.vault.handle[handle].Secret
	join.Sign(secret)
	data := join.Serialize()
	return s.Send(data), token
}

func (s *Safe) Signin(handle, password, email string) bool {
	token, err := s.vault.NewUser(handle, password, email)
	if err != nil {
		return false
	}
	s.users[handle] = &User{token, make([]crypto.Token, 0), false}
	join := attorney.JoinNetwork{
		Epoch:   s.epoch,
		Author:  token,
		Handle:  handle,
		Details: "",
	}
	secret := s.vault.handle[handle].Secret
	join.Sign(secret)
	data := join.Serialize()
	return s.Send(data)
}
