package csp

import (
	"golang.org/x/net/html/charset"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
)

func TestClient(t *testing.T) {
	conn, err := net.Dial("tcp", "www.cryptopro.ru:4444")
	if err != nil {
		t.Fatal(err)
	}

	store, err := SystemStore("MY")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	crt, err := store.GetBySubjectId("4370ccf78043a2c9cb0016802c410e1789168774")
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

			crt, err := store.GetBySubjectId("4370ccf78043a2c9cb0016802c410e1789168774")
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
