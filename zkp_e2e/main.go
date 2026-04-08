package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	modeE2E  = "e2e"
	modePerf = "perf"
)

type registerReq struct {
	Username   string `json:"username"`
	PublicKeyY string `json:"publicKeyY"`
	Salt       string `json:"salt"`
}

type challengeReq struct {
	Username string `json:"username"`
	ClientR  string `json:"clientR"`
}

type verifyReq struct {
	ChallengeID string `json:"challengeId"`
	S           string `json:"s"`
	ClientR     string `json:"clientR"`
	Username    string `json:"username"`
}

type challengeResp struct {
	ChallengeID string `json:"challengeId"`
	C           string `json:"c"`
	P           string `json:"p"`
	Q           string `json:"q"`
	G           string `json:"g"`
}

type verifyResp struct {
	Token     string `json:"token"`
	Type      string `json:"type"`
	ExpiresIn int64  `json:"expiresIn"`
}

type errorResp struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"requestId"`
}

type flowInputs struct {
	register          registerReq
	challenge         challengeReq
	verify            verifyReq
	checkChallengeHex bool
	expectedChallenge string
}

func randomInRange(max *big.Int) (*big.Int, error) {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	if n.Sign() == 0 {
		return big.NewInt(1), nil
	}
	return n, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func challengeHashHex(clientRHex, publicYHex, username string) string {
	raw := clientRHex + "|" + publicYHex + "|" + username
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func parseHexBig(s string) (*big.Int, error) {
	n := new(big.Int)
	_, ok := n.SetString(strings.TrimSpace(s), 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex: %s", s)
	}
	return n, nil
}

func currentMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("ZKP_TEST_MODE")))
	switch mode {
	case modePerf:
		return modePerf
	default:
		return modeE2E
	}
}

func buildFlowInputs(mode, username, salt string, p, q, g *big.Int) (*flowInputs, error) {
	if mode == modePerf {
		return &flowInputs{
			register: registerReq{
				Username:   username,
				PublicKeyY: "1",
				Salt:       salt,
			},
			challenge: challengeReq{
				Username: username,
				ClientR:  "1",
			},
			verify: verifyReq{
				S:        "0",
				ClientR:  "1",
				Username: username,
			},
			checkChallengeHex: false,
		}, nil
	}

	x, err := randomInRange(q)
	if err != nil {
		return nil, err
	}
	y := new(big.Int).Exp(g, x, p)

	r, err := randomInRange(q)
	if err != nil {
		return nil, err
	}
	R := new(big.Int).Exp(g, r, p)

	register := registerReq{
		Username:   username,
		PublicKeyY: y.Text(16),
		Salt:       salt,
	}
	challenge := challengeReq{
		Username: username,
		ClientR:  R.Text(16),
	}
	localCHex := challengeHashHex(challenge.ClientR, register.PublicKeyY, username)
	cVal, err := parseHexBig(localCHex)
	if err != nil {
		return nil, err
	}
	s := new(big.Int).Mul(cVal, x)
	s.Add(s, r)
	s.Mod(s, q)

	return &flowInputs{
		register:          register,
		challenge:         challenge,
		verify:            verifyReq{S: s.Text(16), ClientR: challenge.ClientR, Username: username},
		checkChallengeHex: true,
		expectedChallenge: localCHex,
	}, nil
}

func postJSON[T any](client *http.Client, url string, reqBody any, out *T) error {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var e errorResp
		if err := json.Unmarshal(body, &e); err == nil && e.Message != "" {
			return fmt.Errorf("%s %s failed: status=%d code=%s message=%s", req.Method, url, resp.StatusCode, e.Code, e.Message)
		}
		return fmt.Errorf("%s %s failed: status=%d body=%s", req.Method, url, resp.StatusCode, string(body))
	}

	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("decode response failed: %w, body=%s", err, string(body))
		}
	}
	return nil
}

func getMe(client *http.Client, baseURL, token string) error {
	url := baseURL + "/api/v1/me"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s failed: status=%d body=%s", url, resp.StatusCode, string(body))
	}
	fmt.Printf("[4/4] me ok: %s\n", string(body))
	return nil
}

func main() {
	mode := currentMode()

	baseURL := os.Getenv("BASE_URL")
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "http://localhost:8080"
	}
	baseURL = strings.TrimRight(baseURL, "/")

	timeoutSec := 15
	if s := os.Getenv("TIMEOUT_SECONDS"); strings.TrimSpace(s) != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			timeoutSec = v
		}
	}

	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}

	randSuffix, err := randomHex(4)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init random failed: %v\n", err)
		os.Exit(1)
	}
	username := "e2e_" + randSuffix
	salt, err := randomHex(16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "salt random failed: %v\n", err)
		os.Exit(1)
	}

	g := big.NewInt(2)
	pHex1536 := "" +
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
	p, err := parseHexBig(pHex1536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse p failed: %v\n", err)
		os.Exit(1)
	}
	q := new(big.Int).Sub(p, big.NewInt(1))
	q.Div(q, big.NewInt(2))

	inputs, err := buildFlowInputs(mode, username, salt, p, q, g)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build flow inputs failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Base URL: %s\n", baseURL)
	fmt.Printf("Mode: %s\n", mode)
	fmt.Printf("Username: %s\n", username)

	registerURL := baseURL + "/api/v1/auth/register"
	if err := postJSON[struct{}](client, registerURL, registerReq{
		Username:   inputs.register.Username,
		PublicKeyY: inputs.register.PublicKeyY,
		Salt:       inputs.register.Salt,
	}, nil); err != nil {
		fmt.Fprintf(os.Stderr, "[1/4] register failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("[1/4] register ok")

	challengeURL := baseURL + "/api/v1/auth/challenge"
	var challenge challengeResp
	if err := postJSON(client, challengeURL, challengeReq{
		Username: inputs.challenge.Username,
		ClientR:  inputs.challenge.ClientR,
	}, &challenge); err != nil {
		fmt.Fprintf(os.Stderr, "[2/4] challenge failed: %v\n", err)
		os.Exit(1)
	}
	if challenge.ChallengeID == "" || challenge.C == "" {
		fmt.Fprintln(os.Stderr, "[2/4] challenge invalid response")
		os.Exit(1)
	}
	fmt.Printf("[2/4] challenge ok: challengeId=%s\n", challenge.ChallengeID)

	if inputs.checkChallengeHex {
		if !strings.EqualFold(inputs.expectedChallenge, challenge.C) {
			fmt.Fprintf(os.Stderr, "[3/4] challenge hash mismatch: local=%s remote=%s\n", inputs.expectedChallenge, challenge.C)
			os.Exit(1)
		}
	}

	verifyURL := baseURL + "/api/v1/auth/verify"
	var verify verifyResp
	if err := postJSON(client, verifyURL, verifyReq{
		ChallengeID: challenge.ChallengeID,
		S:           inputs.verify.S,
		ClientR:     inputs.verify.ClientR,
		Username:    inputs.verify.Username,
	}, &verify); err != nil {
		fmt.Fprintf(os.Stderr, "[3/4] verify failed: %v\n", err)
		os.Exit(1)
	}
	if verify.Token == "" {
		fmt.Fprintln(os.Stderr, "[3/4] verify invalid response: empty token")
		os.Exit(1)
	}
	fmt.Println("[3/4] verify ok: token received")

	if err := getMe(client, baseURL, verify.Token); err != nil {
		fmt.Fprintf(os.Stderr, "[4/4] me failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s success: register -> challenge -> verify -> me\n", strings.ToUpper(mode))
}
