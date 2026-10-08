package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sheng-Wu163/data/internal/api"
	"github.com/Sheng-Wu163/data/internal/fingerprint"
	"github.com/Sheng-Wu163/data/internal/model"
	"github.com/Sheng-Wu163/data/rules"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	set, err := rules.Load("")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return httptest.NewServer(api.New(fingerprint.New(set)).Handler())
}

func TestHealth(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %v", body["status"])
	}
}

func TestFingerprintArray(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	payload := `[
		{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
		{"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
		{"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
	]`

	resp := post(t, srv.URL+"/fingerprint", payload)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var results []model.Result
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("len = %d, want 3", len(results))
	}
	if results[0].Protocol != "SSH" || results[1].Product != "nginx" || results[2].Protocol != "unknown" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestFingerprintEnvelope(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := post(t, srv.URL+"/fingerprint", `{"items":[{"ip":"1.2.3.15","port":6379,"banner":"+PONG"}]}`)
	defer resp.Body.Close()

	var results []model.Result
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Protocol != "Redis" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestFingerprintSingleObject(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := post(t, srv.URL+"/fingerprint", `{"ip":"1.2.3.9","port":21,"banner":"220 ProFTPD 1.3.7 Server (ProFTPD)"}`)
	defer resp.Body.Close()

	var results []model.Result
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Product != "ProFTPD" {
		t.Fatalf("unexpected results: %+v", results)
	}
}

func TestFingerprintEmptyArray(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := post(t, srv.URL+"/fingerprint", `[]`)
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(raw)) != "[]" {
		t.Fatalf("body = %q, want []", string(raw))
	}
}

func TestFingerprintBadJSON(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp := post(t, srv.URL+"/fingerprint", `{not json`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestFingerprintWrongMethod(t *testing.T) {
	srv := newServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
