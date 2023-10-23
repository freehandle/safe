package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/freehandle/axe/attorney"
	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/breeze/util"
	"github.com/freehandle/synergy/api"

	"github.com/freehandle/breeze/socket"
)

type Safe struct {
	file      *os.File
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
	grant := attorney.GrantPowerOfAttorney{
		Epoch:       0,
		Author:      user.Secret.PublicKey(),
		Attorney:    token,
		Fingerprint: []byte(fingerprint),
	}
	grant.Sign(user.Secret)
	fmt.Printf("%+v\n", grant)
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
		Author:  token,
		Handle:  handle,
		Details: "",
	}
	join.Sign(secret)
	fmt.Printf("%+v\n", join)
	data := join.Serialize()
	fmt.Println(data)

	bytes := make([]byte, 0)
	util.PutSecret(secret, &bytes)
	util.PutToken(token, &bytes)
	util.PutString(handle, &bytes)
	util.PutString(password, &bytes)

	size := make([]byte, 0)
	util.PutUint16(uint16(len(bytes)), &size)
	bytes = append(size, bytes...)

	s.file.Seek(0, 2)
	if n, err := s.file.Write(bytes); n != len(bytes) {
		panic(err)
	}

	return s.Send(data)
}

func ReadUsers(file *os.File) map[string]*User {
	data, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	position := 0
	users := make(map[string]*User)
	for {
		position = position + 2
		var pk crypto.PrivateKey
		var token crypto.Token
		var handle string
		var password string
		pk, position = util.ParseSecret(data, position)
		token, position = util.ParseToken(data, position)
		handle, position = util.ParseString(data, position)
		fmt.Println("---------->", handle, position)
		password, position = util.ParseString(data, position)
		users[handle] = &User{
			Handle:    handle,
			Password:  password,
			Secret:    pk,
			Token:     token,
			Attorneys: make([]crypto.Token, 0),
		}
		if position >= len(data) {
			break
		}
	}
	return users
}
