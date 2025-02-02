package safe

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const cookieName = "safeSessionCookie"

type UserView struct {
	Handle    string
	Attorneys []string
	Error     string
	Live      bool
}

func (s *Safe) UserHandleView(handle string) UserView {
	user, ok := s.users[handle]
	if !ok {
		return UserView{
			Error: "user not found",
		}
	}
	view := UserView{
		Handle:    handle,
		Attorneys: make([]string, len(user.Attorneys)),
		Live:      user.Confirmed,
	}
	for n, grantee := range user.Attorneys {
		view.Attorneys[n] = hex.EncodeToString(grantee[:])
	}
	return view
}

func (s *Safe) RevokePOAHandler(w http.ResponseWriter, r *http.Request) {
	handle := s.Handle(r)
	if handle == "" {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	revoking := r.URL.Path
	revoking = strings.Replace(revoking, "/revoke/", "", 1)
	err := s.RevokePower(handle, revoking)
	if err != nil {
		log.Printf("error granting/revoking power: %v", err)
	}
	http.Redirect(w, r, fmt.Sprintf("%v/", s.serverName), http.StatusSeeOther)
}

func (s *Safe) PoAHandler(w http.ResponseWriter, r *http.Request) {
	handle := s.Handle(r)
	if handle == "" {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		return
	}
	attorney := r.FormValue("attorney")
	fingerprint := r.FormValue("fingerprint")
	poa := r.FormValue("poa")
	var err error
	if poa == "grant" {
		err = s.GrantPower(handle, attorney, fingerprint)
	} else {
		err = s.RevokePower(handle, attorney)
	}
	if err != nil {
		log.Printf("error granting/revoking power: %v", err)
	}
	http.Redirect(w, r, fmt.Sprintf("%v/", s.serverName), http.StatusSeeOther)
}

func (s *Safe) GrantHandler(w http.ResponseWriter, r *http.Request) {
	handle := s.Handle(r)
	if handle == "" {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	if err := s.templates.ExecuteTemplate(w, "grant.html", ""); err != nil {
		log.Println(err)
	}
}

func (s *Safe) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	handle := s.Handle(r)
	if handle == "" {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	if err := s.templates.ExecuteTemplate(w, "revoke.html", ""); err != nil {
		log.Println(err)
	}
}

func (s *Safe) LoginHandler(w http.ResponseWriter, r *http.Request) {
	handle := s.Handle(r)
	if handle != "" {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	if err := s.templates.ExecuteTemplate(w, "login.html", ""); err != nil {
		log.Println(err)
	}
}

func (s *Safe) SigninHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.templates.ExecuteTemplate(w, "signin.html", ""); err != nil {
		log.Println(err)
	}
}

func (s *Safe) UserHandler(w http.ResponseWriter, r *http.Request) {
	handle := s.Handle(r)
	if handle == "" {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	view := s.UserHandleView(handle)
	if err := s.templates.ExecuteTemplate(w, "main.html", view); err != nil {
		log.Println(err)
	}
}

func (s *Safe) CredentialsHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		return
	}
	handle := r.FormValue("handle")
	password := r.FormValue("password")
	if !s.CheckCredentials(handle, password) {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	cookie := s.CreateSession(handle)
	fmt.Println("cookie", url.QueryEscape(cookie))
	if cookie == "" {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}

	httpCookie := &http.Cookie{
		Name:     cookieName,
		Value:    url.QueryEscape(cookie),
		MaxAge:   60 * 60 * 24 * 7,
		Secure:   true,
		HttpOnly: true,
	}

	http.SetCookie(w, httpCookie)
	http.Redirect(w, r, fmt.Sprintf("%v/", s.serverName), http.StatusSeeOther)
}

func (s *Safe) NewUserHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		return
	}
	handle := r.FormValue("handle")
	password := r.FormValue("password")
	email := r.FormValue("email")

	_, ok := s.users[handle]
	if ok {
		http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
		return
	}
	s.Signin(handle, password, email)
	http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
}

func (s *Safe) SignoutHandlewr(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(cookieName); err == nil {
		if token, ok := s.Session.Get(cookie.Value); ok {
			for _, user := range s.users {
				if user.Token.Equal(token) {
					s.Session.Unset(user.Token, cookie.Value)
				}
			}
		}
	}
	http.Redirect(w, r, fmt.Sprintf("%v/login", s.serverName), http.StatusSeeOther)
}
