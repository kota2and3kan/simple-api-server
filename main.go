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
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

const (
	defaultListenAddr  = "localhost:8080"
	defaultPort        = "8080"
	defaultPath        = "api"
	pathListSeparator  = ","
	statusSeparator    = ":"
	forbiddenPathChars = "{}?#" + statusSeparator
	defaultStatus      = http.StatusOK
	minStatus          = 200
	maxStatus          = 599
)

type endpoint struct {
	Path   string
	Status int
}

type config struct {
	ListenAddr      string
	Endpoints       []endpoint
	LogExcludePaths []string
	TLSCertFile     string
	TLSKeyFile      string
}

func (c config) tlsEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func normalizePath(raw string) (string, error) {
	p := strings.Trim(strings.TrimSpace(raw), "/")
	if p == "" {
		return "", errors.New("path is empty")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			return "", fmt.Errorf("path %q has an empty segment", raw)
		}
		if strings.ContainsFunc(seg, isUnsafePathRune) {
			return "", fmt.Errorf("path segment %q must not contain whitespace or control characters", seg)
		}
		if strings.ContainsAny(seg, forbiddenPathChars) {
			return "", fmt.Errorf("path segment %q must not contain any of %q", seg, forbiddenPathChars)
		}
	}
	return p, nil
}

func isUnsafePathRune(r rune) bool {
	return unicode.IsSpace(r) || unicode.IsControl(r)
}

func normalizeListenAddr(raw string) (string, error) {
	if !strings.Contains(raw, ":") {
		raw = net.JoinHostPort(raw, defaultPort)
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil {
		return "", err
	}
	if port == "" {
		port = defaultPort
	}
	if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		return "", fmt.Errorf("address %s: invalid port %q", raw, port)
	}
	return net.JoinHostPort(host, port), nil
}

func loadConfig() (config, error) {
	listenAddr, err := normalizeListenAddr(getEnv("SIMPLE_API_SERVER_LISTEN_ADDR", defaultListenAddr))
	if err != nil {
		return config{}, fmt.Errorf("SIMPLE_API_SERVER_LISTEN_ADDR: %w", err)
	}

	endpoints, err := parseEndpointList("SIMPLE_API_SERVER_PATH_LIST", getEnv("SIMPLE_API_SERVER_PATH_LIST", defaultPath))
	if err != nil {
		return config{}, err
	}
	if len(endpoints) == 0 {
		return config{}, errors.New("SIMPLE_API_SERVER_PATH_LIST: no path given")
	}

	logExcludePaths, err := parsePathList("SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST", getEnv("SIMPLE_API_SERVER_LOG_EXCLUDE_PATH_LIST", ""))
	if err != nil {
		return config{}, err
	}

	certFile := getEnv("SIMPLE_API_SERVER_TLS_CERT_FILE", "")
	keyFile := getEnv("SIMPLE_API_SERVER_TLS_KEY_FILE", "")
	switch {
	case certFile != "" && keyFile == "":
		return config{}, errors.New("SIMPLE_API_SERVER_TLS_KEY_FILE: must be set together with SIMPLE_API_SERVER_TLS_CERT_FILE")
	case certFile == "" && keyFile != "":
		return config{}, errors.New("SIMPLE_API_SERVER_TLS_CERT_FILE: must be set together with SIMPLE_API_SERVER_TLS_KEY_FILE")
	}

	return config{
		ListenAddr:      listenAddr,
		Endpoints:       endpoints,
		LogExcludePaths: logExcludePaths,
		TLSCertFile:     certFile,
		TLSKeyFile:      keyFile,
	}, nil
}

func newTLSConfig(cfg config) (*tls.Config, error) {
	if !cfg.tlsEnabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("TLS key pair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func parsePathList(key, raw string) ([]string, error) {
	seen := map[string]bool{}
	var paths []string
	for _, entry := range strings.Split(raw, pathListSeparator) {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		p, err := normalizePath(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	return paths, nil
}

func parseEndpointList(key, raw string) ([]endpoint, error) {
	seen := map[string]int{}
	var endpoints []endpoint
	for _, entry := range strings.Split(raw, pathListSeparator) {
		if strings.TrimSpace(entry) == "" {
			continue
		}
		ep, err := parseEndpoint(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		if status, ok := seen[ep.Path]; ok {
			if status != ep.Status {
				return nil, fmt.Errorf("%s: path %q is listed with both status code %d and %d",
					key, ep.Path, status, ep.Status)
			}
			continue
		}
		seen[ep.Path] = ep.Status
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

func parseEndpoint(raw string) (endpoint, error) {
	rawPath, rawStatus, hasStatus := strings.Cut(raw, statusSeparator)
	path, err := normalizePath(rawPath)
	if err != nil {
		return endpoint{}, err
	}
	status := defaultStatus
	if hasStatus {
		if status, err = parseStatus(rawStatus); err != nil {
			return endpoint{}, fmt.Errorf("path %q: %w", path, err)
		}
	}
	return endpoint{Path: path, Status: status}, nil
}

func parseStatus(raw string) (int, error) {
	status, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || status < minStatus || status > maxStatus {
		return 0, fmt.Errorf("status code %q must be an integer between %d and %d",
			strings.TrimSpace(raw), minStatus, maxStatus)
	}
	return status, nil
}

type apiResponse struct {
	API    string `json:"API"`
	Status int    `json:"status"`
}

func bodyAllowedForStatus(status int) bool {
	return status != http.StatusNoContent && status != http.StatusNotModified
}

func apiHandler(logger *log.Logger, ep endpoint) http.HandlerFunc {
	body, _ := json.Marshal(apiResponse{API: ep.Path, Status: ep.Status})
	body = append(body, '\n')
	withBody := bodyAllowedForStatus(ep.Status)
	return func(w http.ResponseWriter, r *http.Request) {
		if withBody {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(ep.Status)
		if !withBody {
			return
		}
		if _, err := w.Write(body); err != nil {
			logger.Printf("write error: %s %s: %v", r.RemoteAddr, r.URL.Path, err)
		}
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func accessLog(logger *log.Logger, cfg config, next http.Handler) http.Handler {
	excluded := map[string]bool{}
	for _, p := range cfg.LogExcludePaths {
		excluded[routePath(p)] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if excluded[r.URL.Path] {
			return
		}
		logger.Printf("%s %s %s %s %d %dB %s %q",
			r.RemoteAddr, r.Method, r.URL.Path, r.Proto,
			rec.status, rec.bytes, time.Since(start), r.UserAgent())
	})
}

func routePath(path string) string {
	return "/" + path
}

func newMux(logger *log.Logger, cfg config) *http.ServeMux {
	mux := http.NewServeMux()
	for _, ep := range cfg.Endpoints {
		route := routePath(ep.Path)
		mux.HandleFunc(route, apiHandler(logger, ep))
		logger.Printf("registered endpoint: %s -> %d", route, ep.Status)
	}
	return mux
}

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags)
	cfg, err := loadConfig()
	if err != nil {
		logger.Fatalf("invalid configuration: %v", err)
	}

	tlsConfig, err := newTLSConfig(cfg)
	if err != nil {
		logger.Fatalf("invalid configuration: %v", err)
	}

	mux := newMux(logger, cfg)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           accessLog(logger, cfg, mux),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         tlsConfig,
	}

	go func() {
		var err error
		if cfg.tlsEnabled() {
			logger.Printf("listening on https://%s", srv.Addr)
			err = srv.ListenAndServeTLS("", "")
		} else {
			logger.Printf("listening on http://%s", srv.Addr)
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("server error: %v", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Printf("shutdown error: %v", err)
	}
}
