package gosteam

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	auth "github.com/bbqtd/go-steam-authenticator"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	API_URL       = "https://api.steampowered.com"
	COMMUNITY_URL = "https://steamcommunity.com"
	STORE_URL     = "https://store.steampowered.com"
)

type Client struct {
	HttpClient     *http.Client
	Auth           *auth.Authenticator
	sharedSecret   string
	identitySecret string
	apiKey         string
	username       string
	password       string
}

func NewClient(username string, password string, apiKey string, sharedSecret string, identitySecret string) (*Client, error) {
	client := &Client{
		HttpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		sharedSecret:   sharedSecret,
		identitySecret: identitySecret,
		apiKey:         apiKey,
		username:       username,
		password:       password,
	}
	authenticator, err := auth.New(sharedSecret, identitySecret, func() uint64 {
		return auth.CurrentTime()
	})
	if err != nil {
		return client, err
	}
	client.Auth = authenticator

	return client, nil
}

// TODO: Return login status so we can handle e.g. captcha.
func (c *Client) Login() error {
	rsakey, err := c.getRsaKey()
	if err != nil {
		return err
	}
	pass, err := c.encryptPassword(rsakey)
	if err != nil {
		return err
	}
	resp, err := c.doLogin(rsakey, pass, "")
	if err != nil {
		return err
	}

	if resp.Requires2FA {
		a := c.Auth.AuthCode()
		resp, err = c.doLogin(rsakey, pass, a)
		if err != nil {
			return err
		}
	}
	log.Printf("%#v", resp)
	return nil
}

type loginKeyResponse struct {
	Success      bool   `json:"success"`
	PublicKeyMod string `json:"publickey_mod"`
	PublicKeyExp string `json:"publickey_exp"`
	Timestamp    string `json:"timestamp"`
}

type doLoginResponse struct {
	Success       bool   `json:"success"`
	Requires2FA   bool   `json:"requires_twofactor"`
	CaptchaNeeded bool   `json:"captcha_needed"`
	CaptchaGid    string `json:"captcha_gid"`
}

func (c *Client) getRsaKey() (loginKeyResponse, error) {
	var keyResp loginKeyResponse

	resp, err := http.PostForm(COMMUNITY_URL+"/login/getrsakey", url.Values{
		"username": []string{c.username},
	})
	if err != nil {
		return keyResp, err
	}

	err = json.NewDecoder(resp.Body).Decode(&keyResp)
	if err != nil {
		return keyResp, err
	}

	if !keyResp.Success {
		return keyResp, fmt.Errorf("received success = false from steam on RSA key fetch")
	}

	return keyResp, nil
}

func (c *Client) encryptPassword(rsaKey loginKeyResponse) (string, error) {
	mod := big.Int{}
	mod.SetString(rsaKey.PublicKeyMod, 16)
	exp, err := strconv.ParseInt(rsaKey.PublicKeyExp, 16, 64)

	if err != nil {
		return "", err
	}

	pk := &rsa.PublicKey{
		N: &mod,
		E: int(exp),
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pk, []byte(c.password))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (c *Client) doLogin(lkr loginKeyResponse, pass string, code string) (doLoginResponse, error) {
	var loginResp doLoginResponse

	resp, err := http.PostForm(COMMUNITY_URL+"/login/dologin", url.Values{
		"password":          []string{pass},
		"username":          []string{c.username},
		"twofactorcode":     []string{code},
		"loginfriendlyname": []string{},
		"captchagid":        []string{"-1"},
		"captcha_text":      []string{},
		"emailsteamid":      []string{},
		"rsatimestamp":      []string{lkr.Timestamp},
		"remember_login":    []string{"false"},
	})
	if err != nil {
		return loginResp, err
	}
	err = json.NewDecoder(resp.Body).Decode(&loginResp)
	if err != nil {
		return loginResp, err
	}
	return loginResp, nil
}
