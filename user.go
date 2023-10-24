package safe

import (
	"github.com/freehandle/axe/attorney"
	"github.com/freehandle/breeze/crypto"
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
