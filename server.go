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

func NewLocalServer(ctx context.Context, safeCfg SafeConfig, passwd string, gateway Sender, receive chan []byte) (chan error, *Safe) {
	finalize := make(chan error, 2)
	safe, err := newServerFromSendReceiver(ctx, safeCfg, passwd, gateway, finalize)
	if err != nil {
		finalize <- err
		return finalize, nil
	}

	go func() {
		for {
			select {
			case action, ok := <-receive:
				if !ok {
					return
				}
				if len(action) == 0 {
					continue
				}
				if action[0] == 0 {
					continue
				}
				action = action[1:]
				switch attorney.Kind(action) {
				case attorney.GrantPowerOfAttorneyType:
					if grant := attorney.ParseGrantPowerOfAttorney(action); grant != nil {
						safe.IncorporateGrant(grant)
					}
				case attorney.RevokePowerOfAttorneyType:
					if revoke := attorney.ParseRevokePowerOfAttorney(action); revoke != nil {
						safe.IncorporateRevoke(revoke)
					}
				case attorney.JoinNetworkType:
					if join := attorney.ParseJoinNetwork(action); join != nil {
						safe.IncorporateJoin(join)
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return finalize, safe
}

func NewServer(ctx context.Context, safeCfg SafeConfig, cfg GatewayConfig, passwd string) chan error {
	finalize := make(chan error, 2)
	gatewayConn, err := socket.Dial("localhost", cfg.Gateway.Addr, safeCfg.Credentials, cfg.Gateway.Token)
	if err != nil {
		finalize <- fmt.Errorf("could not connect to gateway host: %v", err)
		return finalize
	}
	var blocks chan *handles.HandlesBlock
	if cfg.Simple == nil {
		sources := socket.NewTrustedAgregator(ctx, "localhost", safeCfg.Credentials, 1, cfg.Providers, nil)
		if sources == nil {
			finalize <- fmt.Errorf("could not connect to providers")
			return finalize
		}
		blocks = handles.HandlesListener(ctx, sources)
	} else {
		fmt.Println("Using simple file-based handle listener")
		blocks = handles.LocalHandleListener(ctx, cfg.Simple.Path, cfg.Simple.Name, cfg.Simple.Interval)
	}
	safe, err := newServerFromSendReceiver(ctx, safeCfg, passwd, gatewayConn, finalize)

	if safeCfg.RestAPIPort != 0 {
		fmt.Print("vamos la...............")
		go NewSafeRestAPI(safeCfg.RestAPIPort, safe)
	}
	if err != nil {
		finalize <- err
	}
	go func() {
		for {
			select {
			case block, ok := <-blocks:
				if !ok {
					return
				}
				for _, grant := range block.Grant {
					safe.IncorporateGrant(grant)
					fmt.Println(attorney.ToString(grant.Serialize()))
					fmt.Println("---")
				}
				for _, revoke := range block.Revoke {
					safe.IncorporateRevoke(revoke)
					fmt.Println(attorney.ToString(revoke.Serialize()))
					fmt.Println("---")
				}
				for _, join := range block.Join {
					safe.IncorporateJoin(join)
					fmt.Printf(attorney.ToString(join.Serialize()))
				}

				safe.epoch = block.Epoch
			case <-ctx.Done():
				return
			}
		}
	}()
	return finalize
}

func newServerFromSendReceiver(ctx context.Context, config SafeConfig, passwd string, gateway Sender, finalize chan error) (*Safe, error) {
	vault, err := OpenVaultFromPassword([]byte(passwd), fmt.Sprintf("%v/vault.dat", config.Path))
	if err != nil {
		return nil, fmt.Errorf("could not open vault: %v", err)
	}
	safe := &Safe{
		vault:      vault,
		epoch:      1,
		gateway:    gateway,
		users:      make(map[string]*User),
		Session:    util.OpenCokieStore(fmt.Sprintf("%v/cookies.dat", config.Path), 0),
		serverName: config.ServerName,
		pending:    make(map[string]*attorney.GrantPowerOfAttorney),
	}

	for handle, user := range vault.handle {
		safe.users[handle] = &User{
			Token:     user.Secret.PublicKey(),
			Attorneys: make([]crypto.Token, 0),
		}
	}
	safe.actions, err = OpenSafeDatabase(fmt.Sprintf("%v/safe.dat", config.Path), attorney.GetHashes)
	if err != nil {
		return nil, fmt.Errorf("could not open safe database: %v", err)
	}

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
	mux.HandleFunc("/confirm/", safe.ConfirmHandler)
	srv := &http.Server{
		Addr:         fmt.Sprintf("localhost:%v", config.Port),
		Handler:      mux,
		WriteTimeout: 2 * time.Second,
	}

	go func() {
		<-ctx.Done()
		srv.Shutdown(ctx)
		vault.Close()
		log.Print("safe server shutdown")
	}()

	go func() {
		finalize <- srv.ListenAndServe()
	}()

	return safe, nil
}
