package safe

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/freehandle/breeze/socket"
	"github.com/freehandle/synergy/api"
)

var templateFiles = []string{
	"main", "grant", "revoke", "login", "signin",
}

func NewServer(config SafeConfig, path string) chan error {

	finalize := make(chan error, 2)

	//_, safePK := crypto.RandomAsymetricKey()
	conn, err := socket.Dial(config.AxeAddress, config.Credentials, config.AxeToken)
	if err != nil {
		log.Fatalf("could not connect to host: %v", err)
	}

	gatewayConn, err := socket.Dial(config.GatewayAddress, config.Credentials, config.GatewayToken)
	if err != nil {
		log.Fatalf("could not connect to gateway: %v", err)
	}

	usersFile, err := os.OpenFile("users.dat", os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}

	safe := &Safe{
		file:    usersFile,
		epoch:   0,
		conn:    gatewayConn,
		users:   ReadUsers(usersFile),
		Session: api.OpenCokieStore(fmt.Sprintf("%v/cookies.dat", path), nil),
	}

	for handle, user := range safe.users {
		fmt.Printf("%v: %+v", handle, *user)
	}

	signal := make(chan *Signal)

	go SelfProxyState(conn, signal)
	go NewSynergyNode(safe, signal)

	safe.templates = template.New("root")
	files := make([]string, len(templateFiles))
	for n, file := range templateFiles {
		files[n] = fmt.Sprintf("%v/templates/%v.html", path, file)
	}
	t, err := template.ParseFiles(files...)
	if err != nil {
		log.Fatal(err)
	}
	safe.templates = t

	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir(fmt.Sprintf("%v/static", path)))
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

	finalize <- srv.ListenAndServe()
	return finalize
}
