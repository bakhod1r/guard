package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestAccessTokenConfig(t *testing.T) {
	var f File
	if o, err := f.accessToken(); o != nil || err != nil {
		t.Fatalf("disabled: %v %v", o, err)
	}
	f.AccessToken.Enabled = true
	if _, err := f.accessToken(); err == nil {
		t.Fatal("enabled without keys must fail")
	}
	f.AccessToken.Keys = append(f.AccessToken.Keys, struct {
		ID     string `yaml:"id"`
		Secret string `yaml:"secret"`
	}{ID: "k1", Secret: base64.StdEncoding.EncodeToString([]byte("short"))})
	if _, err := f.accessToken(); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("short key: %v", err)
	}
	f.AccessToken.Keys[0].Secret = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	f.AccessToken.TTL = Duration(3 * time.Hour)
	o, err := f.accessToken()
	if err != nil || o.TTL != 3*time.Hour || len(o.Keys) != 1 || o.Keys[0].ID != "k1" {
		t.Fatalf("options = %+v, %v", o, err)
	}
	if c := f.guardConfig(); c.AccessToken == nil {
		t.Fatal("guardConfig dropped access_token")
	}
}

func TestValidateSessionStoreAndAccessToken(t *testing.T) {
	f := valid(t, "")
	f.Session.Store = "memcached"
	if err := f.Validate(); err == nil || !strings.Contains(err.Error(), "session.store") {
		t.Fatalf("store: %v", err)
	}
	f = valid(t, "")
	f.AccessToken.Enabled = true
	if err := f.Validate(); err == nil || !strings.Contains(err.Error(), "access_token.keys") {
		t.Fatalf("access token: %v", err)
	}
	f.AccessToken.Keys = append(f.AccessToken.Keys, struct {
		ID     string `yaml:"id"`
		Secret string `yaml:"secret"`
	}{ID: "k1", Secret: "not base64!"})
	if _, err := f.accessToken(); err == nil || !strings.Contains(err.Error(), "must be base64") {
		t.Fatalf("base64: %v", err)
	}
}
