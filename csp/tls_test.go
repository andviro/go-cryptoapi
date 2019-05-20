package csp

import (
	"io/ioutil"
	"net"
	"net/http"
	"testing"

	"golang.org/x/net/html/charset"
)

func TestClient(t *testing.T) {
	if authCertSubjectID == "" {
		t.Skip("TLS auth cert subject ID not specified")
	}
	conn, err := net.Dial("tcp", "www.cryptopro.ru:4444")
	if err != nil {
		t.Fatal(err)
	}

	store, err := SystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	crt, err := store.GetBySubjectId(authCertSubjectID)
	if err != nil {
		t.Fatal(err)
	}
	tlsConn, err := Client(conn, Config{
		ServerName:   "www.cryptopro.ru",
		Certificates: []Cert{crt},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = tlsConn.Handshake()
	if err != nil {
		t.Fatal(err)
	}
	err = tlsConn.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReadWrite(t *testing.T) {
	if authCertSubjectID == "" {
		t.Skip("TLS auth cert subject ID not specified")
	}
	tr := &http.Transport{
		Dial: func(network, addr string) (res net.Conn, err error) {
			conn, err := net.Dial(network, addr)
			if err != nil {
				return
			}
			store, err := SystemStore("MY")
			if err != nil {
				return
			}
			defer store.Close()

			crt, err := store.GetBySubjectId(authCertSubjectID)
			if err != nil {
				return
			}
			return Client(conn, Config{
				ServerName:   "www.cryptopro.ru",
				Certificates: []Cert{crt},
			})
		},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://www.cryptopro.ru:4444")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rdr, err := charset.NewReader(resp.Body, resp.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := ioutil.ReadAll(rdr)
	t.Log(string(data))
	if err != nil {
		t.Fatal(err)
	}
}
