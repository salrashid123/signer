package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	sal "github.com/salrashid123/signer/pem"
)

var ()

/*
edit /etc/hosts, add
 127.0.0.1  http.domain.com

*/

func main() {

	caCert, err := ioutil.ReadFile("tls-ca.crt")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	r, err := sal.NewPEMCrypto(&sal.PEM{
		PrivatePEMFile:     "client.key",
		PublicCertFile:     "client.crt",
		SignatureAlgorithm: x509.SHA256WithRSAPSS, // required for go 1.15+ TLS
		ExtTLSConfig: &tls.Config{
			ServerName: "http.domain.com",
			RootCAs:    caCertPool,
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	tr := &http.Transport{
		TLSClientConfig: r.TLSConfig(),
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://http.domain.com:8081")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))

}
