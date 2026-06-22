package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"
)

// Supabase / GoTrue is a first-class auth driver: set AUTH_DRIVER=supabase and
// SUPABASE_URL + SUPABASE_ANON_KEY. Tokens are issued by GoTrue; the middleware
// verifies them with AUTH_SECRET set to your Supabase JWT secret. Firebase,
// WorkOS, Auth0 and OAuth providers ship as separate plugins that depend on this
// package and register their own guard the same way.

var httpClient = &http.Client{Timeout: 10 * time.Second}

func supabaseEnv() (url, key string, err error) {
	url = os.Getenv("SUPABASE_URL")
	key = os.Getenv("SUPABASE_ANON_KEY")
	if url == "" || key == "" {
		return "", "", errors.New("SUPABASE_URL and SUPABASE_ANON_KEY required")
	}
	return url, key, nil
}

func supabaseLogin(ctx context.Context, email, password string) (string, error) {
	return goTrue(ctx, "/auth/v1/token?grant_type=password", map[string]string{"email": email, "password": password})
}

func supabaseSignup(ctx context.Context, email, password string) (string, error) {
	return goTrue(ctx, "/auth/v1/signup", map[string]string{"email": email, "password": password})
}

func goTrue(ctx context.Context, path string, body map[string]string) (string, error) {
	url, key, err := supabaseEnv()
	if err != nil {
		return "", err
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+path, bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", key)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Msg         string `json:"msg"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode >= 300 || out.AccessToken == "" {
		if out.Msg != "" {
			return "", errors.New(out.Msg)
		}
		return "", errors.New("gotrue request failed")
	}
	return out.AccessToken, nil
}
