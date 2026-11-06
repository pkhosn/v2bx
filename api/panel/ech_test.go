package panel

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func echFixture(t *testing.T) (config, key, legacy []byte) {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	contents := []byte{7, 0, 0x20}
	contents = appendECHVector(contents, private.PublicKey().Bytes())
	contents = appendECHVector(contents, []byte{0, 1, 0, 1})
	contents = append(contents, 0, byte(len("public.example")))
	contents = append(contents, []byte("public.example")...)
	contents = append(contents, 0, 0)
	config = appendECHVector([]byte{0xfe, 0x0d}, contents)
	key = appendECHVector(appendECHVector(nil, private.Bytes()), config)
	legacy = appendECHVector(nil, config)
	legacy = append(legacy, 0, 1, 7)
	legacy = appendECHVector(legacy, private.Bytes())
	return
}
func TestECHKeyFormats(t *testing.T) {
	config, key, legacy := echFixture(t)
	for _, old := range []bool{false, true} {
		k, c := key, appendECHVector(nil, config)
		if old {
			k = legacy
			c = config
		}
		settings := TlsSettings{ECH: "custom", ECHKey: base64.StdEncoding.EncodeToString(k), ECHConfig: base64.StdEncoding.EncodeToString(c)}
		encoded, err := settings.ECHKeysPEM()
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(encoded))
		if block == nil || string(block.Bytes) != string(key) {
			t.Fatal("incorrect normalized key")
		}
		settings.ECHKey = encoded
		if _, err = settings.ECHKeysPEM(); err != nil {
			t.Fatal(err)
		}
	}
}
func TestECHInvalidKeysNeverLeak(t *testing.T) {
	config, key, _ := echFixture(t)
	for _, mutation := range []string{"missing", "encoding", "key", "config"} {
		t.Run(mutation, func(t *testing.T) {
			k := append([]byte(nil), key...)
			settings := TlsSettings{ECH: "custom", ECHConfig: base64.StdEncoding.EncodeToString(appendECHVector(nil, config))}
			switch mutation {
			case "missing":
				k = nil
			case "key":
				k[2] ^= 8
			case "config":
				settings.ECHConfig = base64.StdEncoding.EncodeToString([]byte("mismatch"))
			}
			settings.ECHKey = base64.StdEncoding.EncodeToString(k)
			if mutation == "encoding" {
				settings.ECHKey = "secret-invalid-key"
			}
			_, err := settings.ECHKeysPEM()
			if err == nil {
				t.Fatal("bad key accepted")
			}
			if settings.ECHKey != "" && strings.Contains(err.Error(), settings.ECHKey) {
				t.Fatal("private key leaked")
			}
		})
	}
}
func TestTLSSettingsCamelAndSnakeCase(t *testing.T) {
	for _, field := range []string{"serverName", "server_name"} {
		var settings TlsSettings
		if err := json.Unmarshal([]byte(`{"`+field+`":"node.example","ech":"custom","ech_key":"key","ech_config":"config"}`), &settings); err != nil {
			t.Fatal(err)
		}
		if settings.ServerName != "node.example" || settings.ECH != "custom" || settings.ECHKey != "key" {
			t.Fatal("missing TLS fields")
		}
	}
}
