package gorsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
)

func assertArrayEqual(t *testing.T, a []byte, b []byte) {
	if len(a) != len(b) {
		t.Fatal("array not equal!")
		return
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			t.Fatalf("array not equal at position %d, %d != %d", i, a[i], b[i])
			return
		}
	}
}

func getPrivateKey(t *testing.T) (*rsa.PrivateKey, error) {
	keyStr := `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAulpKkdbZlOATjInICepVAd1ZfvE34LU8NAYzu1qMA0LHEEGs
BTFXt7uOBNLBPdhnFgcBy/UF56pj/UxyuSV1msuIvT6Df8h8T8KiqurvYHaldwBx
5pZw6e7kmhqI1GLBdO36VbIKwiWVNqbrBUFb3ykHE5BYtoxz76Wpq2Skg4CNgCNs
7POvHdtF5bS4wPtmBdQbd7GhKl7uM3hsDmKLIJnixuuFvmg49l9cV0FzQKa3hsDp
DtrRAART8f1OUt2gFvC6qYzztWIlcWvsNI36V31Ysn2FKCj54bkoG3tKEES5snkJ
T9tq0aKrY7Pm+ClNRW6b1sZwO3XWsLhhuG6FNQIDAQABAoIBAQCfYSfT0ZBnvrmZ
giGfMVag8KJhaoci3X5u9Dr8avXCuDMumSw5iLkAAB33zBTQAywvb7C+soHpYBaC
hga8iOgrixYY3MV03ZBMWyfqzGIM+4yK2cuQrmxF9zZ3AmiyVQAmNH7dGhgPcjtK
8bmh1gNwOlO+DL+C6V8iwGn7l2kIucuOF4PWQ3TMuKauiieAHFBYDnXZK4uoo0sO
QNxD2hggOwZTJeyA6vbcJQkG2byYvy01NbHRaWkgFgLhwlJKiJq8PwhZCA9MOB+M
AerHo3bB/EOqjQx89mkVLksLK8I9uPrXTtRhGf2+l7GzGr48PG2H783q1bRb2lyK
I/JLG9WFAoGBAO/IL8afsRAHq0nAzZz5jNU98Z/AOJuiDiJ0/LeHkJfAdotXrJ0j
Jxe2gkE2lhdWSqK9kozF8zeIibKb8ru2vbXKHUpjo3Vvn+z1wpYr/EdH0k4Gf1W5
pvzVNl/yu7vP0orZ33sZoAVkQBHe0Ki0DY7UKzzJeTo7QLQhodw1CCALAoGBAMb0
+rJ+K3cQGOLsPfIg/zROPIOCmH2qHkGBCRr/y9p918cx4PdPKVziQOCOttf7rggr
V16vyl7+iFUJTkE8SRswV0d6Wy4iSGPKD6OpKrqDT7BSrmdveyasGUI3okcQaA8x
kAZp3iyjx4HxmtwOYEEHM1TrOO1Dtov5Sdi13Pe/AoGBAJ5/7JzWCJv5Bc/N49yE
1QRMWwDndkPiXoeGX1sOAJVfQr0fKloA16GEIhvrclFg2Bs1Rr9JRlmKJsNq9IwC
4upc/PmkXXOOYt+nIIZV8wBHSIwNHXTUML7mTXglItWmLZ1dIa3kpXOK7hMh/znV
MzUbqK0Y3MqSSlYH+U9vurw7AoGASKDdc5NDYq9ppkz/QAhzoTB+PrPJ3vXfHaJx
JH4EeLo/ruOycBVh0Bp3/IGclbO2kBziRBqAEbVxJznCa2YKefZnphwwdOLm8iat
Ft2GT5fn20ITkIbNugxRHC8a+j4u/nzlSrIS/NC8397G3VYSJSrvviwwF80EMozK
PGYHSBkCgYEAwIIXrVLvCGPreHH1KwaAaumAvvGPpCUvmStlhTCkAvcIj8/OCStP
2MASCi5VYxLMtsHH8ok695W72DIvbS7yDcjPFDwHv8Emh/aNu2ONixOCz1Zl5c6x
mQ0OYTr5owsThzKndtob9NCeWAsIpt0t/XPQCl88BaV1AcgaH8L3gQY=
-----END RSA PRIVATE KEY-----`
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		t.Fatalf("decode private key failed")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func getPublicKey(t *testing.T) (*rsa.PublicKey, error) {
	certStr := `-----BEGIN CERTIFICATE-----
MIIDWjCCAkICCQDZBwaWkizumDANBgkqhkiG9w0BAQsFADBvMQswCQYDVQQGEwJj
bjELMAkGA1UECAwCZ2QxCzAJBgNVBAcMAnpoMQ0wCwYDVQQKDARhcGk3MQ0wCwYD
VQQLDARhcGk3MQ0wCwYDVQQDDARhcGk3MRkwFwYJKoZIhvcNAQkBFgpjc0BhcGk3
LmFpMB4XDTIyMDQyMjA0MjExMVoXDTIzMDQyMjA0MjExMVowbzELMAkGA1UEBhMC
Y24xCzAJBgNVBAgMAmdkMQswCQYDVQQHDAJ6aDENMAsGA1UECgwEYXBpNzENMAsG
A1UECwwEYXBpNzENMAsGA1UEAwwEYXBpNzEZMBcGCSqGSIb3DQEJARYKY3NAYXBp
Ny5haTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALpaSpHW2ZTgE4yJ
yAnqVQHdWX7xN+C1PDQGM7tajANCxxBBrAUxV7e7jgTSwT3YZxYHAcv1BeeqY/1M
crkldZrLiL0+g3/IfE/Coqrq72B2pXcAceaWcOnu5JoaiNRiwXTt+lWyCsIllTam
6wVBW98pBxOQWLaMc++lqatkpIOAjYAjbOzzrx3bReW0uMD7ZgXUG3exoSpe7jN4
bA5iiyCZ4sbrhb5oOPZfXFdBc0Cmt4bA6Q7a0QAEU/H9TlLdoBbwuqmM87ViJXFr
7DSN+ld9WLJ9hSgo+eG5KBt7ShBEubJ5CU/batGiq2Oz5vgpTUVum9bGcDt11rC4
YbhuhTUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAuA/Xf6Y5QjhryMM5t0aSednA
yup1HBO57nla6hMXzqiEfaZBIIjQ5iIYHq1vUX2EbDvqAvn+S/FFraseYr4693wZ
CYX9NR6joH6TNHqJOYJe3OlKJfNnbY/5fd5iEyAefXw+c9JnYll6w/yD6mnHbbjs
GL0sRsOQN+uFokoD1uPeGgmdmKATxiY16KKiHyAaWz83wlh7jkXm4DkIjgmDUTk1
+S3VOw1p+1mTMVCN/hJR8ZF+x1TbBbib6cgRd07h6/ABetNbUZoPot+NhfJ1eYK0
0m7XVhHuitfZuKgCSuzk32pqSq6vBGDgiiRn2Z6I24HUTWZtM+py1KuJJQgNMg==
-----END CERTIFICATE-----`
	block, _ := pem.Decode([]byte(certStr))
	if block == nil {
		t.Fatalf("decode certifacte key failed")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certifacte key failed, err=%s", err)
	}
	pub := cert.PublicKey.(*rsa.PublicKey)

	return pub, nil
}

func TestRSACryptString(t *testing.T) {
	tests := []struct {
		data string
	}{
		{
			data: "abcdefghijklnmopqrstuvwxyz!@#$%^&*()_+=-0987654321 ,.……￥，。、`~/|中文{}【】《》，。、；「",
		},
		{
			data: `{
				"id": 122,
				"name": "《阿斯顿风格》",
				"bool": true,
				"hosts": ["*.api7.com"],
				"time": 12134984799,
				"label": {
					"group": "test"
				}
			}`,
		},
	}

	for _, tc := range tests {
		privateKey, err := getPrivateKey(t)
		if err != nil {
			t.Fatalf("get private key failed, err=%s", err)
		}
		publicKey, err := getPublicKey(t)
		if err != nil {
			t.Fatalf("get public key failed, err=%s", err)
		}

		// test string - encrypt
		encrypted, err := PrivateEncrypt(privateKey, []byte(tc.data))
		if err != nil {
			t.Fatalf("encrypt with private key failed, err=%s", err)
		}
		// test string - decrypt
		decrypted, err := PublicDecrypt(publicKey, encrypted)
		if err != nil {
			t.Fatalf("decrypt with public key failed")
		}
		assert.Equal(t, tc.data, string(decrypted))
	}

}

func TestRSACrypt(t *testing.T) {
	tests := []struct {
		data []byte
	}{
		{
			data: []byte{},
		},
		{
			data: []byte{0xff, 0xff, 0xff, 0x00, 0x00},
		},
		{
			data: []byte{0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			data: []byte{0xff, 0xff, 0xff, 0xff, 0xff},
		},
		{
			data: []byte{0xff},
		},
		{
			data: []byte{0x00},
		},
	}

	for _, tc := range tests {
		privateKey, err := getPrivateKey(t)
		if err != nil {
			t.Fatalf("get private key failed, err=%s", err)
		}
		publicKey, err := getPublicKey(t)
		if err != nil {
			t.Fatalf("get public key failed, err=%s", err)
		}

		encrypted, err := PrivateEncrypt(privateKey, tc.data)
		if err != nil {
			t.Fatalf("encrypt with private key failed, err=%s", err)
		}
		decrypted, err := PublicDecrypt(publicKey, encrypted)
		if err != nil {
			t.Fatalf("decrypt with public key failed, err=%s", err)
		}
		assertArrayEqual(t, tc.data, decrypted)
	}
}
