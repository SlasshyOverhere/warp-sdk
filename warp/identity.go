package warp

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var b64 = base64.StdEncoding

type Identity struct {
	ID            string
	Token         string
	License       string
	PrivateKey    string
	PublicKey     string
	PeerPublicKey string
	Endpoint      string
	Ports         []int
	AddressV4     netip.Prefix
	AddressV6     netip.Prefix

	doc registrationDoc
}

type registrationDoc struct {
	ID      string              `json:"id"`
	Token   string              `json:"token"`
	Type    string              `json:"type"`
	Config  registrationConfig  `json:"config"`
	Account registrationAccount `json:"account"`
}

type registrationConfig struct {
	Peers     []registrationPeer    `json:"peers"`
	Interface registrationInterface `json:"interface"`
}

type registrationPeer struct {
	PublicKey string               `json:"public_key"`
	Endpoint  registrationEndpoint `json:"endpoint"`
}

type registrationEndpoint struct {
	Host  string `json:"host"`
	V4    string `json:"v4"`
	V6    string `json:"v6"`
	Ports []int  `json:"ports"`
}

type registrationInterface struct {
	Addresses registrationAddresses `json:"addresses"`
}

type registrationAddresses struct {
	V4 string `json:"v4"`
	V6 string `json:"v6"`
}

type registrationAccount struct {
	License     string `json:"license"`
	AccountType string `json:"account_type"`
	WarpPlus    bool   `json:"warp_plus"`
}

type registerRequest struct {
	InstallID   string `json:"install_id"`
	FcmToken    string `json:"fcm_token"`
	Tos         string `json:"tos"`
	Key         string `json:"key"`
	Type        string `json:"type"`
	Model       string `json:"model"`
	Locale      string `json:"locale"`
	WarpEnabled bool   `json:"warp_enabled"`
}

func generateKeys() (priv, pub []byte, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

func identityFromDoc(priv string, doc registrationDoc) (*Identity, error) {
	if doc.ID == "" || doc.Token == "" {
		return nil, errors.New("warp: registration document missing id or token")
	}
	if len(doc.Config.Peers) == 0 {
		return nil, errors.New("warp: registration document has no peers")
	}
	addrs := doc.Config.Interface.Addresses
	v4, err := parseInterfaceAddr(addrs.V4, 32)
	if err != nil {
		return nil, fmt.Errorf("warp: bad interface v4 %q: %w", addrs.V4, err)
	}
	v6, err := parseInterfaceAddr(addrs.V6, 128)
	if err != nil {
		return nil, fmt.Errorf("warp: bad interface v6 %q: %w", addrs.V6, err)
	}
	peer := doc.Config.Peers[0]
	if peer.PublicKey == "" {
		return nil, errors.New("warp: registration document peer has no public key")
	}
	privRaw, err := b64.DecodeString(priv)
	if err != nil || len(privRaw) != 32 {
		return nil, fmt.Errorf("warp: bad private key")
	}
	k, err := ecdh.X25519().NewPrivateKey(privRaw)
	if err != nil {
		return nil, fmt.Errorf("warp: bad private key: %w", err)
	}
	return &Identity{
		ID:            doc.ID,
		Token:         doc.Token,
		License:       doc.Account.License,
		PrivateKey:    priv,
		PublicKey:     b64.EncodeToString(k.PublicKey().Bytes()),
		PeerPublicKey: peer.PublicKey,
		Endpoint:      peer.Endpoint.Host,
		Ports:         peer.Endpoint.Ports,
		AddressV4:     v4,
		AddressV6:     v6,
		doc:           doc,
	}, nil
}

func parseInterfaceAddr(s string, bits int) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(ip, bits), nil
}

func Register(ctx context.Context) (*Identity, error) {
	priv, pub, err := generateKeys()
	if err != nil {
		return nil, err
	}
	req := registerRequest{
		Tos:         time.Now().UTC().Format(time.RFC3339Nano),
		Key:         b64.EncodeToString(pub),
		Type:        "Android",
		Model:       "PC",
		Locale:      "en_US",
		WarpEnabled: true,
	}
	var doc registrationDoc
	if err := newAPI("").request(ctx, http.MethodPost, "/reg", req, &doc); err != nil {
		return nil, err
	}
	return identityFromDoc(b64.EncodeToString(priv), doc)
}

func (id *Identity) Get(ctx context.Context) error {
	var doc registrationDoc
	if err := newAPI(id.Token).request(ctx, http.MethodGet, "/reg/"+id.ID, nil, &doc); err != nil {
		return err
	}
	fresh, err := identityFromDoc(id.PrivateKey, doc)
	if err != nil {
		return err
	}
	*id = *fresh
	return nil
}

func (id *Identity) SetLicense(ctx context.Context, license string) error {
	body := map[string]string{"license": license}
	if err := newAPI(id.Token).request(ctx, http.MethodPut, "/reg/"+id.ID+"/account", body, nil); err != nil {
		return err
	}
	return id.Get(ctx)
}

func (id *Identity) Delete(ctx context.Context) error {
	return newAPI(id.Token).request(ctx, http.MethodDelete, "/reg/"+id.ID, nil, nil)
}

type identityFile struct {
	Version    int             `json:"version"`
	PrivateKey string          `json:"private_key"`
	Document   json.RawMessage `json:"document"`
}

func (id *Identity) document() registrationDoc {
	if id.doc.ID != "" {
		return id.doc
	}
	doc := registrationDoc{ID: id.ID, Token: id.Token, Type: "a"}
	doc.Config.Peers = []registrationPeer{{
		PublicKey: id.PeerPublicKey,
		Endpoint: registrationEndpoint{
			Host:  id.Endpoint,
			Ports: id.Ports,
		},
	}}
	doc.Config.Interface.Addresses = registrationAddresses{
		V4: id.AddressV4.String(),
		V6: id.AddressV6.String(),
	}
	doc.Account.License = id.License
	return doc
}

func (id *Identity) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	doc, err := json.Marshal(id.document())
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(identityFile{Version: 1, PrivateKey: id.PrivateKey, Document: doc}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "identity.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func LoadIdentity(dir string) (*Identity, error) {
	b, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		return nil, err
	}
	var f identityFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("warp: parse identity.json: %w", err)
	}
	var doc registrationDoc
	if err := json.Unmarshal(f.Document, &doc); err != nil {
		return nil, fmt.Errorf("warp: parse identity document: %w", err)
	}
	return identityFromDoc(f.PrivateKey, doc)
}

func loadOrRegisterIdentity(ctx context.Context, dir string) (*Identity, error) {
	id, err := LoadIdentity(dir)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	id, err = Register(ctx)
	if err != nil {
		return nil, err
	}
	if err := id.Save(dir); err != nil {
		return nil, err
	}
	return id, nil
}

func (id *Identity) uapi(endpoint netip.AddrPort) (string, error) {
	priv, err := b64.DecodeString(id.PrivateKey)
	if err != nil || len(priv) != 32 {
		return "", errors.New("warp: identity has no valid private key")
	}
	peer, err := b64.DecodeString(id.PeerPublicKey)
	if err != nil || len(peer) != 32 {
		return "", errors.New("warp: identity has no valid peer public key")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(priv))
	b.WriteString("listen_port=0\n")
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(peer))
	fmt.Fprintf(&b, "preshared_key=%s\n", strings.Repeat("00", 32))
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint.String())
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(keepalive.Seconds()))
	b.WriteString("replace_allowed_ips=true\n")
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	return b.String(), nil
}

const keepalive = 25 * time.Second
