package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/crewjam/saml/samlsp"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type Config struct {
	WebServer struct {
		Host string
		Port int
		Root string
		SSL  struct {
			Enabled bool
			Crt     string
			Key     string
		}
	}
	Saml struct {
		RootUrl     string
		MetadataUrl string
	}
}

func main() {
	var config *Config

	_, err := toml.DecodeFile(os.Args[1], &config)
	if err != nil {
		log.Fatal(err)
	}

	saml, err := InitializeSamlMiddleware(config)

	router := chi.NewRouter()

	router.Use(
		middleware.RequestID,
		middleware.GetHead,
		middleware.CleanPath,
		middleware.Logger,
		middleware.Recoverer,
	)

	router.Group(func(router chi.Router) {
		router.Use(middleware.NoCache)

		router.Mount("/saml/", saml)
	})

	router.Group(func(router chi.Router) {
		router.Use(saml.RequireAccount)

		router.Mount("/", http.FileServer(http.Dir(config.WebServer.Root)))
	})

	if config.WebServer.SSL.Enabled {
		log.Fatal(http.ListenAndServeTLS(
			fmt.Sprintf("%s:%d", config.WebServer.Host, config.WebServer.Port),
			config.WebServer.SSL.Crt,
			config.WebServer.SSL.Key,
			router,
		))
	} else {
		log.Fatal(http.ListenAndServe(
			fmt.Sprintf("%s:%d", config.WebServer.Host, config.WebServer.Port),
			router,
		))
	}
}

func InitializeSamlMiddleware(config *Config) (*samlsp.Middleware, error) {
	root, err := url.Parse(config.Saml.RootUrl)
	if err != nil {
		return nil, err
	}

	idpMetadataURL, err := url.Parse(config.Saml.MetadataUrl)
	if err != nil {
		return nil, err
	}

	metadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		return nil, err
	}

	crt, key, err := GenerateSelfSignedCertificate(root.Host, 2048, time.Hour*24*365)
	if err != nil {
		return nil, err
	}

	saml, _ := samlsp.New(samlsp.Options{
		URL:               *root,
		Key:               key,
		Certificate:       crt,
		IDPMetadata:       metadata,
		SignRequest:       true,
		AllowIDPInitiated: true,
	})

	return saml, nil
}

func GenerateSelfSignedCertificate(name string, bits int, lifetime time.Duration) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(lifetime)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	bytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	crt, err := x509.ParseCertificate(bytes)
	if err != nil {
		return nil, nil, err
	}

	return crt, key, nil
}
