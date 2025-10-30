package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/freehandle/breeze/crypto"
	"github.com/freehandle/breeze/middleware/config"
	"github.com/freehandle/safe"
)

type SimpleProviderConfig struct {
	Path     string
	Name     string
	Interval int64
}

type Config struct {
	Token           string                // json:"token"
	CredentialsPath string                // json:"credentialsPath"
	Gateway         config.Peer           // json:"gateway"
	Providers       []config.Peer         // json:"providers"
	Port            int                   // json:"port"
	AdminPort       int                   // json:"adminPort"
	RestAPIPort     int                   // json:"restAPIPort"
	DataPath        string                // json:"dataPath"
	ServerName      string                // json:"serverName"
	SimpleProvider  *SimpleProviderConfig // json:"simpleProvider"
}

func (c Config) Check() error {
	token := crypto.TokenFromString(c.Token)
	if token == crypto.ZeroToken {
		return errors.New("invalid nde token")
	}
	if c.CredentialsPath != "" {
		_, err := config.ParseCredentials(c.CredentialsPath, token)
		if err != nil {
			return fmt.Errorf("could not parse credentials: %v", err)
		}
	}
	return nil
}

func ConfigToGatewayonfig(c Config, pk crypto.PrivateKey) safe.GatewayConfig {
	cfg := safe.GatewayConfig{
		Gateway:     config.PeerToTokenAddr(c.Gateway),
		Credentials: pk,
	}
	if c.SimpleProvider == nil {
		cfg.Providers = config.PeersToTokenAddr(c.Providers)
	} else {
		cfg.Simple = &safe.SimpleBlockProvider{
			Path:     c.SimpleProvider.Path,
			Name:     c.SimpleProvider.Name,
			Interval: time.Duration(c.SimpleProvider.Interval) * time.Second,
		}
	}
	return cfg
}

func ConfigToSafeConfig(c Config, pk crypto.PrivateKey) safe.SafeConfig {
	return safe.SafeConfig{
		Credentials: pk,
		Port:        c.Port,
		Path:        c.DataPath,
		HtmlPath:    "../",
		ServerName:  c.ServerName,
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: safe <path-to-config> <safe-passphrase>")
		os.Exit(1)
	}
	specs, err := config.LoadConfig[Config](os.Args[1])
	if err != nil || specs == nil {
		fmt.Printf("misconfiguarion: %v\n", err)
		os.Exit(1)
	}
	token := crypto.TokenFromString(specs.Token)
	ctx, cancel := context.WithCancel(context.Background())
	var secret crypto.PrivateKey
	if specs.CredentialsPath != "" {
		secret, err = config.ParseCredentials(specs.CredentialsPath, token)
		if err != nil {
			fmt.Printf("could not retrieve credentials from file: %v\n", err)
			cancel()
			os.Exit(1)
		}
	} else {
		keys := config.WaitForRemoteKeysSync(ctx, []crypto.Token{token}, "localhost", specs.AdminPort)
		secret = keys[token]
		if !secret.PublicKey().Equal(token) {
			fmt.Println("could not synchrnize keys")
			os.Exit(1)
		}
	}
	safeCfg := ConfigToSafeConfig(*specs, secret)
	cfg := ConfigToGatewayonfig(*specs, secret)
	err = <-safe.NewServer(ctx, safeCfg, cfg, os.Args[2])
	fmt.Println(err)
}
