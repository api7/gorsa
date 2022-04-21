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
MIIEowIBAAKCAQEAqpV+acc3AZKUDCfflvdoGcFi2QzeN/Jk71wJ/Clnw9hrPdxI
oFDCouRVxB5HJRMNa477sW4nl9tf3oAKblOP5eo2yAQZ/eB4H0Bzvn6+joulOAlb
KvxhmK8vSWGsaK1B65/5Tinl1k37ucLyNdWU4zw/2nb4g49KSNlrTNgQFPL/aKE4
92d+VQn1976//Ph95Q9gkElhRBYIydxmXNSeFaAjpZ3b4peJyRYQ2EoDR+UzsT78
vZLymY2TjvMR0AqDzhTwGB1uv1u0wrAZV+o0OGH76nLPxittWPJVy1h1Et5u37ww
v7sjnoC7UfLtR6Ia1Zu9ObAbAeyM4fHpJV4ZnQIDAQABAoIBAD0mK9O1YyWAKuwU
mxUeCUY6Sbnu3/YEQWSAhN/M4/KTsRXS0oINkUgdPBV6mRxUMRpefiFDkJPiQwKa
uaKE9+9+PzcCKWMVxVnGm/csrhihPI/S4siNAlteaUAP8GLxwNC7Xv5DDK3+9H7J
wFPGBYJTxbwFq95VTlbBAbLhPRqUzfZAFhRvY4d/Nb2vM4Pd901SM8tiXV2RG7Ax
m4yz/6bS9JRN95R6C4saiO+79EOGM5aA687rT18BcAOfAaG28tjLKW53KJnAoXYQ
fuVqVBX+bLChFg9jwMjfOfBsAHWINiC2TAAgtZIibpXlbykAa68bQj1DozVYg9XI
fuUvfU0CgYEA78Wq3zh1f3tSoRWea17cjNa3DZCcTN2ZVpY7MdlVQyzx/nn5jLE4
waJOI6KwwIvGRPwVJyGVLDuk8D5De6KeePMFJ0a+Ja2u29oqPLO+wBzU9LAKbWt0
vXZKm6tgRUHGQQwiBa8aYwyHkQyxd+Bbjz9qFlwTk3XEesTDCsURUKcCgYEAtiEP
bnoYA9p1wGzz9NKSgjAvZ71urRO4YubkCdPHk14TkZz8LAjkeajmSOoYcupiQ1Bq
l1BPsb8cYEQh6exAolMtfKGM41kJRaxXCdp0mUX3gUL0DXwBbT6GybNI6XuL+Qg3
8nCype3YP63l5w2OLHvpTcRoiQ/1BFkXJlIbqBsCgYEAgLKf0erzHncqVe5NtyIW
zb3eSXiqfJOhX5mJsmsOWd1BEy+TZBIn/b9Jo9UKfH9J7/NCw1tCP5jQIme5Px59
YzxGMtvE6mJ8beN/Mk/kfie7oo7vOeYoph1dVIs7RFFWwclqZZSkXC/4gEHI7ChP
3ObT4aaQl2DqEl+UtS4r6hcCgYAnLneWadfOxGm+qvHUwpRYQ6t/Iuazf2GUjV2T
q6bs0jldgytRAdy9O5PHLe1yk2/uUVeNE+8BKz8ciqvNGlFRWpmXjV2070uqXIgh
C4k4DDBR86hzWjEoYmI29EYETNrxCU6X7pzQS5nRIUUrbuQeN84aN93RVsh8Vfo/
+TwP7wKBgHUUAqXj3enHcoOryuJQCGXJ0WEcOS7H8BsnkNnqg3LxEZs5L/dB1wnX
/P5AV1OMto2bde4Ye870MPdYEZ0DKzuMCNaNc5pujYvLs9/HS+6x/1JyK8Ihhv7Y
9Uu5bdtdpyRYzz0RhxXjBKNV2E0N+YTNuOOJTJ0sIIeGDZmT2NQB
-----END RSA PRIVATE KEY-----`
	block, _ := pem.Decode([]byte(keyStr))
	if block == nil {
		t.Fatalf("decode private key failed")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func getPublicKey(t *testing.T) (*rsa.PublicKey, error) {
	certStr := `-----BEGIN CERTIFICATE-----
MIIDXjCCAkagAwIBAgIGAVzOk87KMA0GCSqGSIb3DQEBBQUAMHAxJzAlBgNVBAMM
HuaRqeWunee9kee7nOenkeaKgOaciemZkOWFrOWPuDELMAkGA1UECxMCU0MxETAP
BgNVBAoTCE1vYmFvUGF5MQswCQYDVQQHEwJCSjELMAkGA1UECBMCQkoxCzAJBgNV
BAYTAkNOMB4XDTE3MDYyMjA2NTI0MloXDTE3MDYyMjA2NTQyMlowcDEnMCUGA1UE
Awwe5pGp5a6d572R57uc56eR5oqA5pyJ6ZmQ5YWs5Y+4MQswCQYDVQQLEwJTQzER
MA8GA1UEChMITW9iYW9QYXkxCzAJBgNVBAcTAkJKMQswCQYDVQQIEwJCSjELMAkG
A1UEBhMCQ04wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqlX5pxzcB
kpQMJ9+W92gZwWLZDN438mTvXAn8KWfD2Gs93EigUMKi5FXEHkclEw1rjvuxbieX
21/egApuU4/l6jbIBBn94HgfQHO+fr6Oi6U4CVsq/GGYry9JYaxorUHrn/lOKeXW
Tfu5wvI11ZTjPD/adviDj0pI2WtM2BAU8v9ooTj3Z35VCfX3vr/8+H3lD2CQSWFE
FgjJ3GZc1J4VoCOlndvil4nJFhDYSgNH5TOxPvy9kvKZjZOO8xHQCoPOFPAYHW6/
W7TCsBlX6jQ4Yfvqcs/GK21Y8lXLWHUS3m7fvDC/uyOegLtR8u1HohrVm705sBsB
7Izh8eklXhmdAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAKnVlCYMTDKUGLfZbC5S
+eWy43t3nf+pqzG1WT+Pn85iKs3ye2R9bolvdcPdn1vDvkz7Do8LH4YtpHXUF0fP
coVn8NRCdxf3iux5lut7oPMsOcVrzfgrwz3DQuAALD+cjY0Hw+bGncYBPlrTJK1Z
ai3WpEeoQ21S8WsMGQ4ohwx/nNRCgLSF+fO9tpb9rZOILYdhtzVovZBZk0/DqZCT
mVuKBrdImSUKL1+EAY+D+SPYKgqNT+uLtiUZOo2X+CgPH5AS1pK4Je01oO8uate0
KtBZahhjo4kfFo4fqIJhY6d3+a88SYz5lkKuC2s2JVZQxNqax1j1mLQVPhTc+q3G
rfc=
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
