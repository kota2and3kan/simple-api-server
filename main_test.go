/*
Copyright © 2026 kota2and3kan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		in              string
		want            string
		wantErrContains string
	}{
		{name: "plain", in: "api", want: "api"},
		{name: "surrounding spaces", in: "  api  ", want: "api"},
		{name: "surrounding slashes", in: "/api/", want: "api"},
		{name: "repeated surrounding slashes", in: "///api///", want: "api"},
		{name: "multi segment", in: "admin/users", want: "admin/users"},
		{name: "multi segment with slashes", in: "/a/b/c/", want: "a/b/c"},

		{name: "empty", in: "", wantErrContains: "path is empty"},
		{name: "spaces only", in: "   ", wantErrContains: "path is empty"},
		{name: "slash only", in: "/", wantErrContains: "path is empty"},
		{name: "slashes only", in: "//", wantErrContains: "path is empty"},
		{name: "inner empty segment", in: "a//b", wantErrContains: "empty segment"},
		{name: "wildcard", in: "{id}", wantErrContains: "must not contain"},
		{name: "unbalanced open brace", in: "{id", wantErrContains: "must not contain"},
		{name: "unbalanced close brace", in: "id}", wantErrContains: "must not contain"},
		{name: "wildcard in inner segment", in: "a/{id}/b", wantErrContains: "must not contain"},
		{name: "inner space", in: "my api", wantErrContains: "whitespace"},
		{name: "inner tab", in: "my\tapi", wantErrContains: "whitespace"},
		{name: "inner space in a later segment", in: "a/my api/b", wantErrContains: "whitespace"},
		{name: "control character", in: "a\x00b", wantErrContains: "whitespace or control"},
		{name: "query separator", in: "a?b", wantErrContains: "must not contain"},
		{name: "fragment separator", in: "a#b", wantErrContains: "must not contain"},
		{name: "status separator", in: "a:b", wantErrContains: "must not contain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizePath(tt.in)
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("normalizePath(%q) = %q, nil; want an error", tt.in, got)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("normalizePath(%q) error = %q; want it to contain %q", tt.in, err, tt.wantErrContains)
				}
				if got != "" {
					t.Errorf("normalizePath(%q) = %q on error; want an empty string", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePath(%q) returned an unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("normalizePath(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}

func okEndpoints(paths ...string) []endpoint {
	endpoints := make([]endpoint, 0, len(paths))
	for _, p := range paths {
		endpoints = append(endpoints, endpoint{Path: p, Status: http.StatusOK})
	}
	return endpoints
}

var envKeys = []string{
	"SIMPLE_API_SERVER_LISTEN_ADDR",
	"SIMPLE_API_SERVER_PATH_LIST",
	"SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST",
	"SIMPLE_API_SERVER_TLS_CERT_FILE",
	"SIMPLE_API_SERVER_TLS_KEY_FILE",
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name            string
		env             map[string]string
		want            config
		wantErrContains string
	}{
		{
			name: "nothing set falls back to the defaults",
			env:  nil,
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("api")},
		},
		{
			name: "blank values fall back to the defaults",
			env: map[string]string{
				"SIMPLE_API_SERVER_LISTEN_ADDR": "   ",
				"SIMPLE_API_SERVER_PATH_LIST":   "   ",
			},
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("api")},
		},
		{
			name: "every value overridden",
			env: map[string]string{
				"SIMPLE_API_SERVER_LISTEN_ADDR": "0.0.0.0:9090",
				"SIMPLE_API_SERVER_PATH_LIST":   "users",
			},
			want: config{ListenAddr: "0.0.0.0:9090", Endpoints: okEndpoints("users")},
		},
		{
			name: "surrounding spaces are trimmed",
			env:  map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": "  0.0.0.0:9090  "},
			want: config{ListenAddr: "0.0.0.0:9090", Endpoints: okEndpoints("api")},
		},
		{
			name: "an empty host listens on every interface",
			env:  map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": ":9090"},
			want: config{ListenAddr: ":9090", Endpoints: okEndpoints("api")},
		},
		{
			name: "a listen address without a port falls back to the default port",
			env:  map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": "0.0.0.0"},
			want: config{ListenAddr: "0.0.0.0:8080", Endpoints: okEndpoints("api")},
		},
		{
			name: "a listen address with an empty port falls back to the default port",
			env:  map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": "0.0.0.0:"},
			want: config{ListenAddr: "0.0.0.0:8080", Endpoints: okEndpoints("api")},
		},
		{
			name: "a lone colon listens on every interface on the default port",
			env:  map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": ":"},
			want: config{ListenAddr: ":8080", Endpoints: okEndpoints("api")},
		},
		{
			name: "an ipv6 listen address keeps its brackets",
			env:  map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": "[::1]:"},
			want: config{ListenAddr: "[::1]:8080", Endpoints: okEndpoints("api")},
		},
		{
			name: "path list is split on commas in order",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "users,health,ready"},
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("users", "health", "ready")},
		},
		{
			name: "path list entries are trimmed",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": " api , health "},
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("api", "health")},
		},
		{
			name: "duplicate paths are registered once",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api,health,api"},
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("api", "health")},
		},
		{
			name: "empty path list entries are skipped",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "a,,b"},
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("a", "b")},
		},
		{
			name: "a path list entry may span several segments",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api,admin/users"},
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("api", "admin/users")},
		},
		{
			name: "a path list entry may carry a version segment",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "v1/api,v2/api"},
			want: config{ListenAddr: "localhost:8080", Endpoints: okEndpoints("v1/api", "v2/api")},
		},
		{
			name: "a status code may follow a path",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "v1/foo:200,v1/bar:404,v1/baz:503"},
			want: config{
				ListenAddr: "localhost:8080",
				Endpoints: []endpoint{
					{Path: "v1/foo", Status: 200},
					{Path: "v1/bar", Status: 404},
					{Path: "v1/baz", Status: 503},
				},
			},
		},
		{
			name: "a path without a status code answers with 200",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api,health:503"},
			want: config{
				ListenAddr: "localhost:8080",
				Endpoints: []endpoint{
					{Path: "api", Status: 200},
					{Path: "health", Status: 503},
				},
			},
		},
		{
			name: "spaces around a status code are trimmed",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": " /v1/api/ : 418 "},
			want: config{
				ListenAddr: "localhost:8080",
				Endpoints:  []endpoint{{Path: "v1/api", Status: 418}},
			},
		},
		{
			name: "a repeated path agreeing on its status code is registered once",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:503,health,api:503"},
			want: config{
				ListenAddr: "localhost:8080",
				Endpoints: []endpoint{
					{Path: "api", Status: 503},
					{Path: "health", Status: 200},
				},
			},
		},
		{
			name: "a repeated path agreeing on the default status code is registered once",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api,api:200"},
			want: config{
				ListenAddr: "localhost:8080",
				Endpoints:  []endpoint{{Path: "api", Status: 200}},
			},
		},
		{
			name: "the lowest status code is accepted",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:200"},
			want: config{ListenAddr: "localhost:8080", Endpoints: []endpoint{{Path: "api", Status: 200}}},
		},
		{
			name: "the highest status code is accepted",
			env:  map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:599"},
			want: config{ListenAddr: "localhost:8080", Endpoints: []endpoint{{Path: "api", Status: 599}}},
		},

		{
			name:            "a repeated path disagreeing on its status code is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "healthz,healthz:503"},
			wantErrContains: `path "healthz" is listed with both status code 200 and 503`,
		},
		{
			name:            "a repeated path disagreeing on two explicit status codes is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:503,api:200"},
			wantErrContains: `path "api" is listed with both status code 503 and 200`,
		},
		{
			name:            "a status code below the valid range is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:199"},
			wantErrContains: `status code "199" must be an integer between 200 and 599`,
		},
		{
			name:            "a status code above the valid range is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:600"},
			wantErrContains: "must be an integer between 200 and 599",
		},
		{
			name:            "a non numeric status code is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:abc"},
			wantErrContains: "must be an integer between 200 and 599",
		},
		{
			name:            "an empty status code is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:"},
			wantErrContains: "must be an integer between 200 and 599",
		},
		{
			name:            "a second colon is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api:200:300"},
			wantErrContains: "must be an integer between 200 and 599",
		},
		{
			name:            "a status code without a path is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": ":404"},
			wantErrContains: "path is empty",
		},
		{
			name:            "the rejected path is named",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api,v1/bar:404999"},
			wantErrContains: `path "v1/bar"`,
		},

		{
			name:            "path with an unbalanced brace is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "{id"},
			wantErrContains: "SIMPLE_API_SERVER_PATH_LIST",
		},
		{
			name:            "path with a wildcard is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "api,{id}"},
			wantErrContains: "SIMPLE_API_SERVER_PATH_LIST",
		},
		{
			name:            "path list of only separators is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": ",,,"},
			wantErrContains: "no path given",
		},
		{
			name: "log exclude paths are parsed like the path list",
			env: map[string]string{
				"SIMPLE_API_SERVER_PATH_LIST":             "api,healthz",
				"SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST": " healthz , healthz ,",
			},
			want: config{
				ListenAddr:      "localhost:8080",
				Endpoints:       okEndpoints("api", "healthz"),
				LogExcludePaths: []string{"healthz"},
			},
		},
		{
			name: "a log exclude path need not be a served path",
			env:  map[string]string{"SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST": "admin/users"},
			want: config{
				ListenAddr:      "localhost:8080",
				Endpoints:       okEndpoints("api"),
				LogExcludePaths: []string{"admin/users"},
			},
		},
		{
			name:            "an invalid log exclude path is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST": "{id}"},
			wantErrContains: "SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST",
		},
		{
			name:            "a log exclude path carries no status code",
			env:             map[string]string{"SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST": "healthz:200"},
			wantErrContains: "SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST",
		},
		{
			name:            "a kubernetes service link value is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": "tcp://10.96.99.1:8080"},
			wantErrContains: "SIMPLE_API_SERVER_LISTEN_ADDR",
		},
		{
			name:            "a non numeric port is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": "0.0.0.0:http"},
			wantErrContains: "invalid port",
		},
		{
			name:            "a port above the valid range is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_LISTEN_ADDR": "0.0.0.0:65536"},
			wantErrContains: "invalid port",
		},
		{
			name:            "a path with an inner space is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "my api"},
			wantErrContains: "SIMPLE_API_SERVER_PATH_LIST",
		},
		{
			name:            "a log exclude path with an inner space is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST": "my api"},
			wantErrContains: "SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST",
		},
		{
			name:            "a path containing a query separator is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_PATH_LIST": "a?b"},
			wantErrContains: "SIMPLE_API_SERVER_PATH_LIST",
		},

		{
			name: "a tls key pair is read as a pair",
			env: map[string]string{
				"SIMPLE_API_SERVER_TLS_CERT_FILE": " /tls/tls.crt ",
				"SIMPLE_API_SERVER_TLS_KEY_FILE":  " /tls/tls.key ",
			},
			want: config{
				ListenAddr:  "localhost:8080",
				Endpoints:   okEndpoints("api"),
				TLSCertFile: "/tls/tls.crt",
				TLSKeyFile:  "/tls/tls.key",
			},
		},
		{
			name:            "a certificate without a key is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_TLS_CERT_FILE": "/tls/tls.crt"},
			wantErrContains: "SIMPLE_API_SERVER_TLS_KEY_FILE",
		},
		{
			name:            "a key without a certificate is rejected",
			env:             map[string]string{"SIMPLE_API_SERVER_TLS_KEY_FILE": "/tls/tls.key"},
			wantErrContains: "SIMPLE_API_SERVER_TLS_CERT_FILE",
		},
	}

	for _, tt := range tests {
		// No t.Parallel here: t.Setenv forbids it.
		t.Run(tt.name, func(t *testing.T) {
			for _, key := range envKeys {
				t.Setenv(key, tt.env[key])
			}

			got, err := loadConfig()
			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("loadConfig() = %+v, nil; want an error", got)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("loadConfig() error = %q; want it to contain %q", err, tt.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig() returned an unexpected error: %v", err)
			}
			if got.ListenAddr != tt.want.ListenAddr ||
				got.TLSCertFile != tt.want.TLSCertFile || got.TLSKeyFile != tt.want.TLSKeyFile {
				t.Errorf("loadConfig() = %+v; want %+v", got, tt.want)
			}
			if !slices.Equal(got.Endpoints, tt.want.Endpoints) {
				t.Errorf("loadConfig().Endpoints = %+v; want %+v", got.Endpoints, tt.want.Endpoints)
			}
			if !slices.Equal(got.LogExcludePaths, tt.want.LogExcludePaths) {
				t.Errorf("loadConfig().LogExcludePaths = %q; want %q", got.LogExcludePaths, tt.want.LogExcludePaths)
			}
		})
	}
}

func TestNewMux(t *testing.T) {
	t.Parallel()

	cfg := config{
		ListenAddr: "localhost:8080",
		Endpoints: []endpoint{
			{Path: "api", Status: http.StatusOK},
			{Path: "admin/users", Status: http.StatusOK},
			{Path: "v1/api", Status: http.StatusOK},
		},
	}
	mux := newMux(log.New(io.Discard, "", 0), cfg)

	tests := []struct {
		name            string
		method          string
		target          string
		wantStatus      int
		wantBody        string
		wantContentType string
	}{
		{
			name:            "registered path",
			method:          http.MethodGet,
			target:          "/api",
			wantStatus:      http.StatusOK,
			wantBody:        "{\"API\":\"api\",\"status\":200}\n",
			wantContentType: "application/json",
		},
		{
			name:            "registered multi segment path",
			method:          http.MethodGet,
			target:          "/admin/users",
			wantStatus:      http.StatusOK,
			wantBody:        "{\"API\":\"admin/users\",\"status\":200}\n",
			wantContentType: "application/json",
		},
		{
			name:            "a version segment is served as part of the path",
			method:          http.MethodGet,
			target:          "/v1/api",
			wantStatus:      http.StatusOK,
			wantBody:        "{\"API\":\"v1/api\",\"status\":200}\n",
			wantContentType: "application/json",
		},
		{
			name:            "a leading segment is not a wildcard",
			method:          http.MethodGet,
			target:          "/anything/api",
			wantStatus:      http.StatusNotFound,
			wantContentType: "",
		},
		{
			name:            "an unregistered path is not served",
			method:          http.MethodGet,
			target:          "/health",
			wantStatus:      http.StatusNotFound,
			wantContentType: "",
		},
		{
			name:            "a path is not a prefix match",
			method:          http.MethodGet,
			target:          "/api/extra",
			wantStatus:      http.StatusNotFound,
			wantContentType: "",
		},
		{
			name:            "no method is required",
			method:          http.MethodPost,
			target:          "/api",
			wantStatus:      http.StatusOK,
			wantBody:        "{\"API\":\"api\",\"status\":200}\n",
			wantContentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("%s %s: status = %d; want %d", tt.method, tt.target, rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("%s %s: body = %q; want %q", tt.method, tt.target, rec.Body.String(), tt.wantBody)
			}
			if got := rec.Header().Get("Content-Type"); tt.wantContentType != "" && got != tt.wantContentType {
				t.Errorf("%s %s: Content-Type = %q; want %q", tt.method, tt.target, got, tt.wantContentType)
			}
		})
	}
}

func TestNewMuxResponseCarriesConfiguredPath(t *testing.T) {
	t.Parallel()

	cfg := config{Endpoints: []endpoint{{Path: "v2/api", Status: http.StatusOK}}}
	mux := newMux(log.New(io.Discard, "", 0), cfg)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/api", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v2/api: status = %d; want %d", rec.Code, http.StatusOK)
	}

	var got apiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET /v2/api: body %q is not valid JSON: %v", rec.Body.String(), err)
	}
	want := apiResponse{API: "v2/api", Status: http.StatusOK}
	if got != want {
		t.Errorf("GET /v2/api: body = %+v; want %+v", got, want)
	}
}

func TestNewMuxServesTheConfiguredStatusCode(t *testing.T) {
	t.Parallel()

	cfg := config{
		Endpoints: []endpoint{
			{Path: "v1/foo", Status: http.StatusOK},
			{Path: "v1/bar", Status: http.StatusNotFound},
			{Path: "v1/baz", Status: http.StatusServiceUnavailable},
		},
	}
	mux := newMux(log.New(io.Discard, "", 0), cfg)

	for _, ep := range cfg.Endpoints {
		target := "/" + ep.Path

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if rec.Code != ep.Status {
			t.Errorf("GET %s: status = %d; want %d", target, rec.Code, ep.Status)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("GET %s: Content-Type = %q; want %q", target, got, "application/json")
		}

		var got apiResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("GET %s: body %q is not valid JSON: %v", target, rec.Body.String(), err)
		}
		want := apiResponse{API: ep.Path, Status: ep.Status}
		if got != want {
			t.Errorf("GET %s: body = %+v; want %+v", target, got, want)
		}
	}
}

func TestNewMuxSendsNoBodyWhereTheStatusCodeForbidsOne(t *testing.T) {
	t.Parallel()

	cfg := config{
		Endpoints: []endpoint{
			{Path: "v1/nocontent", Status: http.StatusNoContent},
			{Path: "v1/notmodified", Status: http.StatusNotModified},
		},
	}
	mux := newMux(log.New(io.Discard, "", 0), cfg)

	for _, ep := range cfg.Endpoints {
		target := "/" + ep.Path

		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if rec.Code != ep.Status {
			t.Errorf("GET %s: status = %d; want %d", target, rec.Code, ep.Status)
		}
		if rec.Body.Len() != 0 {
			t.Errorf("GET %s: body = %q; want an empty body", target, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "" {
			t.Errorf("GET %s: Content-Type = %q; want it unset", target, got)
		}
	}
}

func TestAccessLogExcludesConfiguredPaths(t *testing.T) {
	t.Parallel()

	cfg := config{
		Endpoints:       okEndpoints("v1/payment", "v1/healthz"),
		LogExcludePaths: []string{"v1/healthz"},
	}
	var logged bytes.Buffer
	handler := accessLog(log.New(&logged, "", 0), cfg, newMux(log.New(io.Discard, "", 0), cfg))

	for _, target := range []string{"/v1/healthz", "/v1/payment", "/v1/nope"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

		if target == "/v1/healthz" && rec.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d; want %d (excluding a path must not stop it being served)",
				target, rec.Code, http.StatusOK)
		}
	}

	got := logged.String()
	if strings.Contains(got, "/v1/healthz") {
		t.Errorf("the excluded path was logged:\n%s", got)
	}
	for _, want := range []string{"/v1/payment", "/v1/nope"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is missing from the access log:\n%s", want, got)
		}
	}
}

func writeTestKeyPair(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "simple-api-server test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling the key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	write := func(name string, block *pem.Block) {
		if err := os.WriteFile(name, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	write(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the certificate: %v", err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(cert)

	return certFile, keyFile, roots
}

func TestNewTLSConfig(t *testing.T) {
	t.Parallel()

	certFile, keyFile, _ := writeTestKeyPair(t)

	t.Run("without a key pair the server stays on plain http", func(t *testing.T) {
		t.Parallel()

		got, err := newTLSConfig(config{ListenAddr: "localhost:8080"})
		if err != nil {
			t.Fatalf("newTLSConfig() returned an unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("newTLSConfig() = %+v; want nil", got)
		}
	})

	t.Run("a key pair is loaded", func(t *testing.T) {
		t.Parallel()

		got, err := newTLSConfig(config{TLSCertFile: certFile, TLSKeyFile: keyFile})
		if err != nil {
			t.Fatalf("newTLSConfig() returned an unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("newTLSConfig() = nil; want a TLS configuration")
		}
		if len(got.Certificates) != 1 {
			t.Errorf("newTLSConfig().Certificates has %d entries; want 1", len(got.Certificates))
		}
		if got.MinVersion != tls.VersionTLS12 {
			t.Errorf("newTLSConfig().MinVersion = %#x; want %#x", got.MinVersion, tls.VersionTLS12)
		}
	})

	t.Run("a missing certificate file is reported", func(t *testing.T) {
		t.Parallel()

		got, err := newTLSConfig(config{TLSCertFile: filepath.Join(t.TempDir(), "absent.crt"), TLSKeyFile: keyFile})
		if err == nil {
			t.Fatalf("newTLSConfig() = %+v, nil; want an error", got)
		}
		if !strings.Contains(err.Error(), "TLS key pair") {
			t.Errorf("newTLSConfig() error = %q; want it to contain %q", err, "TLS key pair")
		}
	})

	t.Run("a certificate that does not match the key is reported", func(t *testing.T) {
		t.Parallel()

		_, otherKeyFile, _ := writeTestKeyPair(t)

		if got, err := newTLSConfig(config{TLSCertFile: certFile, TLSKeyFile: otherKeyFile}); err == nil {
			t.Fatalf("newTLSConfig() = %+v, nil; want an error", got)
		}
	})
}

func TestServerServesHTTPSWithTheConfiguredKeyPair(t *testing.T) {
	t.Parallel()

	certFile, keyFile, roots := writeTestKeyPair(t)
	cfg := config{
		Endpoints:   okEndpoints("v1/api"),
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}

	tlsConfig, err := newTLSConfig(cfg)
	if err != nil {
		t.Fatalf("newTLSConfig() returned an unexpected error: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	srv := &http.Server{
		Handler:           newMux(log.New(io.Discard, "", 0), cfg),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         tlsConfig,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	addr := ln.Addr().String()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get("https://" + addr + "/v1/api")
	if err != nil {
		t.Fatalf("GET https://%s/v1/api: %v", addr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET https://%s/v1/api: status = %d; want %d", addr, resp.StatusCode, http.StatusOK)
	}
	if resp.TLS == nil {
		t.Error("the response did not come over TLS")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if want := "{\"API\":\"v1/api\",\"status\":200}\n"; string(body) != want {
		t.Errorf("GET https://%s/v1/api: body = %q; want %q", addr, body, want)
	}

	plain, err := client.Get("http://" + addr + "/v1/api")
	if err != nil {
		t.Fatalf("GET http://%s/v1/api: %v", addr, err)
	}
	defer func() { _ = plain.Body.Close() }()

	if plain.StatusCode != http.StatusBadRequest {
		t.Errorf("GET http://%s/v1/api: status = %d; want %d", addr, plain.StatusCode, http.StatusBadRequest)
	}
	plainBody, err := io.ReadAll(plain.Body)
	if err != nil {
		t.Fatalf("reading the body: %v", err)
	}
	if strings.Contains(string(plainBody), "\"API\"") {
		t.Errorf("GET http://%s/v1/api: the endpoint answered over plain http: %q", addr, plainBody)
	}
}
