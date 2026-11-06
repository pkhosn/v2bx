package panel

import (
	"bytes"
	"crypto/ecdh"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// UnmarshalJSON accepts the panel's legacy camelCase TLS hostname as well as
// snake_case. ECH private material must never be included in error messages.
func (t *TlsSettings) UnmarshalJSON(data []byte) error {
	type settings TlsSettings
	var raw struct {
		*settings
		LegacyServerName string `json:"serverName"`
	}
	raw.settings = (*settings)(t)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if t.ServerName == "" {
		t.ServerName = raw.LegacyServerName
	}
	return nil
}

// ValidateECH rejects unsupported combinations before the node wizard writes
// configuration. Cloudflare mode is a client-to-edge setting, not a VPS key.
func (n *NodeInfo) ValidateECH(core string) error {
	if n.VAllss == nil || n.VAllss.TlsSettings.ECH != "custom" {
		return nil
	}
	if n.Security != Tls {
		return fmt.Errorf("custom ECH requires ordinary TLS")
	}
	if core != "sing" {
		return fmt.Errorf("custom ECH currently requires the sing core")
	}
	_, err := n.VAllss.TlsSettings.ECHKeysPEM()
	return err
}

// ECHKeysPEM validates and converts panel ECH keys to sing's canonical PEM.
// Canonical binary: repeated uint16(private key length), private key,
// uint16(ECHConfig length), ECHConfig. Early panels used an indexed layout;
// accept that layout without rotating already issued keys.
func (t *TlsSettings) ECHKeysPEM() (string, error) {
	if t.ECH != "custom" {
		return "", nil
	}
	raw, err := decodeECH(t.ECHKey, "ECH KEYS")
	if err != nil {
		return "", fmt.Errorf("custom ECH: invalid server key encoding")
	}
	keys, err := parseECHKeys(raw)
	if err != nil {
		keys, err = parseLegacyECHKeys(raw)
		if err != nil {
			return "", fmt.Errorf("custom ECH: invalid server key format")
		}
	}
	canonical := []byte{}
	configs := []byte{}
	for _, key := range keys {
		if err := validateECHKey(key); err != nil {
			return "", err
		}
		canonical = appendECHVector(canonical, key.PrivateKey)
		canonical = appendECHVector(canonical, key.Config)
		configs = append(configs, key.Config...)
	}
	if t.ECHConfig == "" {
		return "", fmt.Errorf("custom ECH: missing client config")
	}
	public, err := decodeECH(t.ECHConfig, "ECH CONFIGS")
	if err != nil {
		return "", fmt.Errorf("custom ECH: invalid client config encoding")
	}
	// Accept the old panel's bare ECHConfig as well as the standard ECHConfigList.
	if !bytes.Equal(public, configs) && !bytes.Equal(public, appendECHVector(nil, configs)) {
		return "", fmt.Errorf("custom ECH: client config does not match server keys")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "ECH KEYS", Bytes: canonical})), nil
}

func decodeECH(value, kind string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "-----BEGIN ") {
		block, rest := pem.Decode([]byte(value))
		if block == nil || block.Type != kind || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("invalid PEM")
		}
		return block.Bytes, nil
	}
	return base64.StdEncoding.DecodeString(value)
}
func appendECHVector(dst, value []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(value)))
	return append(dst, value...)
}
func parseECHKeys(raw []byte) ([]tls.EncryptedClientHelloKey, error) {
	input := cryptobyte.String(raw)
	var keys []tls.EncryptedClientHelloKey
	for !input.Empty() {
		var private, config cryptobyte.String
		if !input.ReadUint16LengthPrefixed(&private) || len(private) != 32 || !input.ReadUint16LengthPrefixed(&config) || len(config) < 5 {
			return nil, fmt.Errorf("invalid key entry")
		}
		keys = append(keys, tls.EncryptedClientHelloKey{PrivateKey: private, Config: config})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("missing keys")
	}
	return keys, nil
}
func parseLegacyECHKeys(raw []byte) ([]tls.EncryptedClientHelloKey, error) {
	input := cryptobyte.String(raw)
	var configs cryptobyte.String
	var count uint16
	if !input.ReadUint16LengthPrefixed(&configs) || !input.ReadUint16(&count) || count != 1 {
		return nil, fmt.Errorf("invalid legacy key")
	}
	var id uint8
	var private cryptobyte.String
	if !input.ReadUint8(&id) || !input.ReadUint16LengthPrefixed(&private) || len(private) != 32 || !input.Empty() || len(configs) < 5 || configs[4] != id {
		return nil, fmt.Errorf("invalid legacy key")
	}
	return []tls.EncryptedClientHelloKey{{PrivateKey: private, Config: configs}}, nil
}
func validateECHKey(key tls.EncryptedClientHelloKey) error {
	config := cryptobyte.String(key.Config)
	var version uint16
	var contents cryptobyte.String
	if !config.ReadUint16(&version) || version != 0xfe0d || !config.ReadUint16LengthPrefixed(&contents) || !config.Empty() {
		return fmt.Errorf("custom ECH: invalid ECHConfig")
	}
	var id, maxLength uint8
	var kem uint16
	var public, suites, name, extensions cryptobyte.String
	if !contents.ReadUint8(&id) || !contents.ReadUint16(&kem) || kem != 0x20 || !contents.ReadUint16LengthPrefixed(&public) || len(public) != 32 || !contents.ReadUint16LengthPrefixed(&suites) || len(suites) == 0 || len(suites)%4 != 0 || !contents.ReadUint8(&maxLength) || !contents.ReadUint8LengthPrefixed(&name) || len(name) == 0 || !contents.ReadUint16LengthPrefixed(&extensions) || !contents.Empty() {
		return fmt.Errorf("custom ECH: unsupported or malformed ECHConfig")
	}
	private, err := ecdh.X25519().NewPrivateKey(key.PrivateKey)
	if err != nil || !bytes.Equal(private.PublicKey().Bytes(), public) {
		return fmt.Errorf("custom ECH: public/private key mismatch")
	}
	return nil
}
