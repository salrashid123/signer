// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	sal "github.com/salrashid123/signer/pem"

	"golang.org/x/net/http2"
)

var (
	cfg = &argConfig{}
)

type argConfig struct {
	flCA         string
	flPort       string
	flServerCert string
	flServerKey  string
	flTPMDevice  string
	flTPMFile    string
}

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	fmt.Fprint(w, "ok")
}

func main() {

	flag.StringVar(&cfg.flCA, "cacert", "tls-ca.crt", "path-to-cacert")
	flag.StringVar(&cfg.flPort, "port", ":8081", "listen port (:8081)")
	flag.StringVar(&cfg.flServerCert, "servercert", "server.crt", "Server certificate (x509)")
	flag.StringVar(&cfg.flServerKey, "serverkey", "server.key", "Server private key")
	flag.StringVar(&cfg.flTPMDevice, "tpmdevice", "/dev/tpm0", "TPM Device to use")
	flag.StringVar(&cfg.flTPMFile, "tpmfile", "key.bin", "TPM File to use")

	flag.Parse()

	argError := func(s string, v ...interface{}) {
		//flag.PrintDefaults()
		log.Fatalf("Invalid Argument error: "+s, v...)
	}
	if cfg.flCA == "" {
		argError("-cacert not specified")
	}

	caCert, err := ioutil.ReadFile(cfg.flCA)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewPEMCrypto(&sal.PEM{
		PrivatePEMFile:     cfg.flServerKey,
		PublicCertFile:     cfg.flServerCert,
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			ServerName: "http.domain.com",
			RootCAs:    caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caCertPool,
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", fronthandler)

	var server *http.Server
	server = &http.Server{
		Addr:      cfg.flPort,
		TLSConfig: r.TLSConfig(),
	}
	http2.ConfigureServer(server, &http2.Server{})
	log.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")
	log.Fatalf("Unable to start Server %v", err)
}
