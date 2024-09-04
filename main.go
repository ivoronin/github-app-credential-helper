package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	githubAPIURL = "https://api.github.com"
)

var (
	ErrInvalidPrivateKey = errors.New("failed to decode PEM block containing private key")
	ErrHTTPError         = errors.New("HTTP error")
)

type GitHubApp struct {
	AppID          int64
	InstallationID int64
	PrivateKey     *rsa.PrivateKey
}

func NewGitHubApp(appID, installationID int64, privateKey *rsa.PrivateKey) *GitHubApp {
	return &GitHubApp{
		AppID:          appID,
		InstallationID: installationID,
		PrivateKey:     privateKey,
	}
}

func (app *GitHubApp) GetAccessToken() (string, error) {
	jwtToken, err := app.generateJWT()
	if err != nil {
		return "", fmt.Errorf("error generating JWT: %w", err)
	}

	accessToken, err := app.exchangeJWTforAccessToken(jwtToken)
	if err != nil {
		return "", fmt.Errorf("error exchanging JWT for access token: %w", err)
	}

	return accessToken, nil
}

func (app *GitHubApp) generateJWT() (string, error) {
	now := time.Now().UTC()

	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(time.Minute * 10).Unix(),
		"iss": app.AppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	jwtToken, err := token.SignedString(app.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("error signing JWT: %w", err)
	}

	return jwtToken, nil
}

func (app *GitHubApp) exchangeJWTforAccessToken(jwtToken string) (string, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", githubAPIURL, app.InstallationID)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("failed to get installation token, %w status: %s", ErrHTTPError, resp.Status)
	}

	var response struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("error decoding response: %w", err)
	}

	return response.Token, nil
}

func loadPrivateKeyFromPEM(pemFile string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(pemFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, ErrInvalidPrivateKey
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %w", err)
	}

	return privateKey, nil
}

func mustEnv(key string) string {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		log.Fatalf("Environment variable %s must be set", key)
	}

	return value
}

func get() error {
	appIDStr := mustEnv("GITHUB_APP_ID")
	installationIDStr := mustEnv("GITHUB_INSTALLATION_ID")
	privateKeyPath := mustEnv("GITHUB_PRIVATE_KEY_PATH")

	appID, err := strconv.ParseInt(appIDStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
	}

	installationID, err := strconv.ParseInt(installationIDStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid GITHUB_INSTALLATION_ID: %w", err)
	}

	privateKey, err := loadPrivateKeyFromPEM(privateKeyPath)
	if err != nil {
		return fmt.Errorf("error loading private key: %w", err)
	}

	app := NewGitHubApp(appID, installationID, privateKey)

	token, err := app.GetAccessToken()
	if err != nil {
		return fmt.Errorf("error getting access token: %w", err)
	}

	fmt.Printf("username=x-access-token\npassword=%s\n", token)

	return nil
}

func main() {
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s get\n", os.Args[0])
	}

	switch os.Args[1] {
	case "get":
		if err := get(); err != nil {
			log.Fatalf("Fatal: %v", err)
		}
	case "store", "erase":
	default:
		log.Fatalf("Unknown command: %s", os.Args[1])
	}
}
