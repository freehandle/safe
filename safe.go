package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/freehandle/axe/attorney"
	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/synergy/api"

	"github.com/freehandle/breeze/socket"
)

type User struct {
	Handle    string
	Password  string
	Secret    crypto.PrivateKey
	Token     crypto.Token
	Attorneys []crypto.Token
	Confirmed bool
}

func (a *User) GrantPower(grant *attorney.GrantPowerOfAttorney) {
	for _, grantee := range a.Attorneys {
		if grantee.Equal(grant.Attorney) {
			return
		}
	}
	a.Attorneys = append(a.Attorneys, grant.Attorney)
}

func (a *User) RevokePower(revoke *attorney.RevokePowerOfAttorney) {
	for n, grantee := range a.Attorneys {
		if grantee.Equal(revoke.Attorney) {
			a.Attorneys = append(a.Attorneys[:n], a.Attorneys[n+1:]...)
			return
		}
	}
}

type Safe struct {
	epoch     uint64
	conn      *socket.SignedConnection
	users     map[string]*User
	Session   *api.CookieStore
	templates *template.Template
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

func (s *Safe) CheckCredentials(handle, password string) bool {
	user, ok := s.users[handle]
	if !ok {
		return false
	}
	return user.Password == password
}

func (s *Safe) Handle(r *http.Request) string {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	if token, ok := s.Session.Get(cookie.Value); ok {
		for _, user := range s.users {
			if user.Token.Equal(token) {
				return user.Handle
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
	if s.conn == nil {
		log.Print("no connection to send on")
		return false
	}
	err := s.conn.Send(data)
	if err != nil {
		log.Printf("connection error", err)
		return false
	}
	return true
}

func (s *Safe) GrantPower(handle, grantee, fingerprint string) error {
	user, ok := s.users[handle]
	if !ok {
		return errors.New("invalid user")
	}
	var token crypto.Token
	attorneyBytes, _ := hex.DecodeString(grantee)
	if len(attorneyBytes) != crypto.TokenSize {
		return errors.New("invalid attorney")
	}
	copy(token[:], attorneyBytes)
	fingerprintBytes, err := hex.DecodeString(fingerprint)
	if err != nil {
		return errors.New("invalid fingerprint")
	}
	grant := attorney.GrantPowerOfAttorney{
		Epoch:       0,
		Author:      user.Secret.PublicKey(),
		Attorney:    token,
		Fingerprint: fingerprintBytes,
	}
	grant.Sign(user.Secret)
	data := grant.Serialize()
	s.Send(data)
	return nil
}

func (s *Safe) RevokePower(handle, grantee string) error {
	user, ok := s.users[handle]
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
		Epoch:    0,
		Author:   user.Secret.PublicKey(),
		Attorney: token,
	}
	grant.Sign(user.Secret)
	data := grant.Serialize()
	s.Send(data)
	return nil
}

func (s *Safe) Signin(handle, password string) bool {
	if _, ok := s.users[handle]; ok {
		return false
	}
	token, secret := crypto.RandomAsymetricKey()
	s.users[handle] = &User{
		Handle:    handle,
		Password:  password,
		Secret:    secret,
		Token:     token,
		Attorneys: make([]crypto.Token, 0),
	}
	join := attorney.JoinNetwork{
		Epoch:   0,
		Author:  secret.PublicKey(),
		Handle:  handle,
		Details: "",
	}
	join.Sign(secret)
	fmt.Printf("%+v\n", join)
	data := join.Serialize()
	fmt.Println(data)
	return s.Send(data)
}
