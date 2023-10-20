package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/breeze/socket"
	"github.com/freehandle/synergy/api"
)

var templateFiles = []string{
	"main", "grant", "revoke", "login", "signin",
}

func NewServer(host string, hostToken crypto.Token, port int) chan error {

	finalize := make(chan error, 2)

	_, safePK := crypto.RandomAsymetricKey()
	conn, err := socket.Dial(host, safePK, hostToken)
	if err != nil {
		log.Fatalf("could not connect to host: %v", err)
	}

	safe := &Safe{
		epoch:   0,
		conn:    conn,
		users:   make(map[string]*User),
		Session: api.OpenCokieStore("cookies.dat", nil),
	}

	signal := make(chan *Signal)

	go SelfProxyState(conn, signal)
	go NewSynergyNode(safe, signal)

	safe.templates = template.New("root")
	files := make([]string, len(templateFiles))
	for n, file := range templateFiles {
		files[n] = fmt.Sprintf("./templates/%v.html", file)
	}
	t, err := template.ParseFiles(files...)
	if err != nil {
		log.Fatal(err)
	}
	safe.templates = t

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	mux.HandleFunc("/", safe.UserHandler)
	mux.HandleFunc("/login", safe.LoginHandler)
	mux.HandleFunc("/signin", safe.SigninHandler)
	mux.HandleFunc("/credentials", safe.CredentialsHandler)
	mux.HandleFunc("/newuser", safe.NewUserHandler)
	mux.HandleFunc("/grant", safe.GrantHandler)
	mux.HandleFunc("/revoke", safe.RevokeHandler)
	mux.HandleFunc("/poa", safe.PoAHandler)
	mux.HandleFunc("/signout", safe.SignoutHandlewr)

	srv := &http.Server{
		Addr:         fmt.Sprintf("localhost:%v", port),
		Handler:      mux,
		WriteTimeout: 2 * time.Second,
	}

	finalize <- srv.ListenAndServe()
	return finalize
}
