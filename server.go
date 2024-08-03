package safe

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/breeze/socket"
	"github.com/freehandle/breeze/util"
	"github.com/freehandle/handles"
	"github.com/freehandle/handles/attorney"
)

var templateFiles = []string{
	"main", "grant", "revoke", "login", "signin",
}

func NewServer(ctx context.Context, config SafeConfig, passwd string) chan error {
	finalize := make(chan error, 2)
	gatewayConn, err := socket.Dial("localhost", config.Gateway.Addr, config.Credentials, config.Gateway.Token)
	if err != nil {
		finalize <- fmt.Errorf("could not connect to gateway host: %v", err)
		return finalize
	}
	vault, err := OpenVaultFromPassword([]byte(passwd), fmt.Sprintf("%v/vault.dat", config.Path))
	if err != nil {
		finalize <- fmt.Errorf("could not open vault: %v", err)
		return finalize
	}
	safe := &Safe{
		vault:   vault,
		epoch:   1,
		gateway: gatewayConn,
		users:   make(map[string]*User),
		Session: util.OpenCokieStore(fmt.Sprintf("%v/cookies.dat", config.Path), 0),
	}
	for handle, user := range vault.handle {
		safe.users[handle] = &User{
			Token:     user.Secret.PublicKey(),
			Attorneys: make([]crypto.Token, 0),
		}
	}
	safe.actions, err = OpenSafeDatabase(fmt.Sprintf("%v/safe.dat", config.Path), attorney.GetHashes)
	if err != nil {
		finalize <- fmt.Errorf("could not open safe database: %v", err)
		return finalize
	}

	sources := socket.NewTrustedAgregator(ctx, "localhost", config.Credentials, 1, config.Providers, nil)
	if sources == nil {
		finalize <- fmt.Errorf("could not connect to providers")
		return finalize
	}

	blocks := handles.HandlesListener(ctx, sources)
	go func() {
		for {
			block, ok := <-blocks
			if !ok {
				return
			}
			for _, grant := range block.Grant {
				safe.IncorporateGrant(grant)
			}
			for _, revoke := range block.Revoke {
				safe.IncorporateRevoke(revoke)
			}
			for _, join := range block.Join {
				safe.IncorporateJoin(join)
			}
		}
	}()

	safe.templates = template.New("root")
	files := make([]string, len(templateFiles))
	for n, file := range templateFiles {
		files[n] = fmt.Sprintf("%v/templates/%v.html", config.HtmlPath, file)
	}
	t, err := template.ParseFiles(files...)
	if err != nil {
		log.Fatal(err)
	}
	safe.templates = t

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir(fmt.Sprintf("%v/static", config.HtmlPath)))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", safe.UserHandler)
	mux.HandleFunc("/login", safe.LoginHandler)
	mux.HandleFunc("/signin", safe.SigninHandler)
	mux.HandleFunc("/credentials", safe.CredentialsHandler)
	mux.HandleFunc("/newuser", safe.NewUserHandler)
	//mux.HandleFunc("/grant", safe.GrantHandler)
	mux.HandleFunc("/revoke/", safe.RevokePOAHandler)
	mux.HandleFunc("/poa", safe.PoAHandler)
	mux.HandleFunc("/signout", safe.SignoutHandlewr)

	srv := &http.Server{
		Addr:         fmt.Sprintf("localhost:%v", config.Port),
		Handler:      mux,
		WriteTimeout: 2 * time.Second,
	}
	go func() {
		finalize <- srv.ListenAndServe()
	}()
	return finalize
}
