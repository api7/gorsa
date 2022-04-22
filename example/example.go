package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/api7/gorsa"
)

var (
	msg      string
	data     string
	keyPath  string
	certPath string
)

func getPrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func getPublicCert() (*rsa.PublicKey, error) {
	publicCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(publicCert)
	if block == nil {
		return nil, errors.New("decode certifacte key failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certifacte key failed: %s", err)
	}

	return cert.PublicKey.(*rsa.PublicKey), nil
}

func main() {
	flag.StringVar(&keyPath, "key", "", "the path of private key")
	flag.StringVar(&certPath, "cert", "", "the path of public cert")
	flag.StringVar(&msg, "msg", "", "msg to encrypt")
	flag.StringVar(&data, "data", "", "data to decrypt")
	flag.Parse()

	if keyPath == "" && certPath == "" {
		panic("path of key and cert are both empty")
	}

	// encrypt
	if keyPath != "" {
		if msg == "" {
			panic("message to encrypt is empty")
		}
		privateKey, err := getPrivateKey()
		if err != nil {
			panic("failed to load private key, error: " + err.Error())
		}
		encrypted, err := gorsa.PrivateEncrypt(privateKey, []byte(msg))
		if err != nil {
			panic("failed to encrypt message with private key, error:" + err.Error())
		}
		fmt.Println(base64.RawURLEncoding.EncodeToString(encrypted))
		return
	}

	// decrypt
	if data == "" {
		panic("data to decrypt is empty")
	}
	publicCert, err := getPublicCert()
	if err != nil {
		panic("failed to load public cert, error: " + err.Error())
	}
	encrypted, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		panic("failed to base64 decode, error: " + err.Error())
	}
	source, err := gorsa.PublicDecrypt(publicCert, encrypted)
	if err != nil {
		panic("failed to decrypt with public cert")
	}
	fmt.Println(string(source))
}
