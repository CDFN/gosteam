package gosteam

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	HttpClient http.Client
	apiKey     string
	username   string
	password   string
}

func NewClient(username string, password string, apiKey string) *Client {
	return &Client{
		HttpClient: http.Client{
			Timeout: 10 * time.Second,
		},
		apiKey:   apiKey,
		username: username,
		password: password,
	}
}

/*
Login flow:
- /getrsakey/
- encrypt password using former key
-             'password': encrypted_password,
            'username': self.username,
            'twofactorcode': self.one_time_code,
            'emailauth': '',
            'loginfriendlyname': '',
            'captchagid': '-1',
            'captcha_text': '',
            'emailsteamid': '',
            'rsatimestamp': rsa_timestamp,
            'remember_login': 'true',
            'donotcache': str(int(time.time() * 1000))
- /login/dologin
-
*/
func (c *Client) Login() {

}

type loginKeyResponse struct {
	Success      bool   `json:"success"`
	PublicKeyMod string `json:"publickey_mod"`
	PublicKeyExp string `json:"publickey_exp"`
	Timestamp    string `json:"timestamp"`
}
type doLoginResponse struct {
	Success     bool `json:"success"`
	Requires2FA bool `json:"requires_twofactor"`
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

func (c *Client) doLogin(lkr loginKeyResponse, pass string) (doLoginResponse, error) {
	var loginResp doLoginResponse
	resp, err := http.PostForm(COMMUNITY_URL+"/login/dologin", url.Values{
		"password":          []string{pass},
		"username":          []string{c.username},
		"twofactorcode":     []string{},
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
