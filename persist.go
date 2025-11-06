package safe

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/breeze/util"
)

const (
	UserSecretKind byte = iota
)

type UserSecret struct {
	Handle   string
	Password crypto.Hash
	Email    string
	Secret   crypto.PrivateKey
}

func (u UserSecret) Serialize() []byte {
	bytes := []byte{UserSecretKind}
	util.PutString(u.Handle, &bytes)
	util.PutHash(u.Password, &bytes)
	util.PutString(u.Email, &bytes)
	util.PutSecret(u.Secret, &bytes)
	return bytes
}

func ParseUserSecret(data []byte) (UserSecret, bool) {
	var user UserSecret
	if data[0] != UserSecretKind {
		return user, false
	}
	position := 1
	user.Handle, position = util.ParseString(data, position)
	user.Password, position = util.ParseHash(data, position)
	user.Email, position = util.ParseString(data, position)
	user.Secret, position = util.ParseSecret(data, position)
	return user, position == len(data)
}

type Vault struct {
	vault  *util.SecureVault
	handle map[string]*UserSecret
}

func (v *Vault) Close() {
	v.vault.Close()
}

func (v *Vault) Check(handle, password string) bool {
	hashed := crypto.Hasher([]byte(password))
	if user, ok := v.handle[handle]; ok {
		return user.Password.Equal(hashed)
	}
	return false
}

func (v *Vault) HandleToEmail(handle string) string {
	if user, ok := v.handle[handle]; ok && user != nil {
		return user.Email
	}
	return ""
}

func (v *Vault) HandleToEmailAndToken(handle string) (string, crypto.Token) {
	if user, ok := v.handle[handle]; ok && user != nil {
		return user.Email, user.Secret.PublicKey()
	}
	return "", crypto.ZeroToken
}

func (v *Vault) FindHandle(handle, email string) *UserSecret {
	if user, ok := v.handle[handle]; ok {
		if user.Email == email {
			return user
		}
	}
	return nil
}

func (v *Vault) FindEmail(email string) []*UserSecret {
	users := make([]*UserSecret, 0)
	for _, user := range v.handle {
		if user.Email == email {
			users = append(users, user)
		}
	}
	return users
}

func (v *Vault) UpdateUser(handle, password, email string) error {
	if user, ok := v.handle[handle]; ok {
		updated := UserSecret{
			Handle:   handle,
			Email:    user.Email,
			Password: user.Password,
			Secret:   user.Secret,
		}
		if password != "" {
			updated.Password = crypto.Hasher([]byte(password))
		}
		if email != "" {
			updated.Email = email
		}
		err := v.vault.NewEntry(updated.Serialize())
		if err != nil {
			return err
		}
		v.handle[handle] = &updated
		return nil
	}
	return errors.New("user not found")
}

func (v *Vault) Secret() crypto.PrivateKey {
	return v.vault.SecretKey
}

func (v *Vault) Token() crypto.Token {
	return v.vault.SecretKey.PublicKey()
}

func OpenVaultFromPassword(passwd []byte, path string) (*Vault, error) {
	vault, err := util.OpenOrCreateVaultFromPassword(passwd, path)
	if err != nil {
		return nil, err
	}
	newVault := Vault{
		vault:  vault,
		handle: make(map[string]*UserSecret),
	}
	for _, entry := range vault.Entries {
		if len(entry) > 0 && entry[0] == UserSecretKind {
			if user, ok := ParseUserSecret(entry); ok {
				newVault.handle[user.Handle] = &user
			}
		}
	}
	return &newVault, nil
}

func (v *Vault) NewUser(handle, password, email string) (crypto.Token, error) {
	if _, ok := v.handle[handle]; ok {
		return crypto.ZeroToken, errors.New("handle already in use")
	}
	token, secret := crypto.RandomAsymetricKey()
	user := UserSecret{
		Handle:   handle,
		Password: crypto.Hasher([]byte(password)),
		Email:    email,
		Secret:   secret,
	}
	err := v.vault.NewEntry(user.Serialize())
	if err != nil {
		return crypto.ZeroToken, err
	}
	v.handle[handle] = &user
	return token, nil
}

// func (v *Vault) ResetPassword(handle, newpassword string) bool {
// 	if usrsecret, ok := v.handle[handle]; ok {
// 		usrsecret.Password = crypto.Hasher([]byte(newpassword))
// 		return true
// 	}

// }

type Database interface {
	SaveAction(msg []byte) error
	LoadIndexedActions(hash crypto.Hash) ([][]byte, error)
	AllTokens() []crypto.Token
}

type lengthOffset struct {
	offset int64
	length int
}

type SafeDatabaseConfig struct {
	VaultPath   string
	ActionsPath string
	Passwd      string
	Indexer     func([]byte) []crypto.Hash
}

type SafeDatabase struct {
	file         *os.File
	actionOffset []lengthOffset
	tokenIndex   map[crypto.Hash][]int
}

func OpenSafeDatabase(path string, indexer func([]byte) []crypto.Hash) (*SafeDatabase, error) {
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	db := SafeDatabase{
		file:         file,
		tokenIndex:   make(map[crypto.Hash][]int),
		actionOffset: make([]lengthOffset, 0),
	}
	offset := int64(0)
	lengthBytes := make([]byte, 2)
	for {
		n, err := file.ReadAt(lengthBytes, offset)
		if n == 0 && err == io.EOF {
			return &db, nil
		}
		if n != 2 {
			return nil, fmt.Errorf("could not read action length on file at position %d: %v", offset, err)
		}
		length := int(lengthBytes[0]) | int(lengthBytes[1])<<8
		bytes := make([]byte, length)
		n, err = file.ReadAt(bytes, offset+2)
		if n != length {
			return nil, fmt.Errorf("could not read action at position %d: %v", offset+2, err)
		}
		db.actionOffset = append(db.actionOffset, lengthOffset{offset, length})
		offset += int64(2 + length)
		for _, hash := range indexer(bytes) {
			db.tokenIndex[hash] = append(db.tokenIndex[hash], len(db.actionOffset)-1)
		}
	}
}

func (s *SafeDatabase) SaveAction(msg []byte) error {
	if len(msg) > 1<<16-1 {
		return errors.New("message too large")
	}
	s.file.Seek(0, 2)
	bytes := make([]byte, 0)
	util.PutUint16(uint16(len(msg)), &bytes)
	bytes = append(bytes, msg...)
	if n, err := s.file.Write(bytes); err != nil {
		return err
	} else if n != len(bytes) {
		return errors.New("failed to write all bytes")
	}
	return nil
}

func (s *SafeDatabase) LoadIndexedActions(hash crypto.Hash) ([][]byte, error) {
	actions := make([][]byte, 0)
	for _, actionSeq := range s.tokenIndex[hash] {
		length := s.actionOffset[actionSeq].length
		action := make([]byte, length)
		n, err := s.file.ReadAt(action, s.actionOffset[actionSeq].offset+2)
		if n != length {
			return nil, fmt.Errorf("could not read action at position %d: %v", s.actionOffset[actionSeq].offset+2, err)
		}
		actions = append(actions, action)
	}
	return actions, nil
}
