// cpagctl is a local HTTP client for the same authenticated API used by the UI.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type storedSession struct {
	Cookie string `json:"cookie"`
	Origin string `json:"origin"`
}

func localOrigin(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("only explicit http://127.0.0.1:port is supported")
	}
	return strings.TrimSuffix(raw, "/"), nil
}
func saveSession(path string, s storedSession) error {
	if f, e := os.Lstat(path); e == nil && (!f.Mode().IsRegular() || f.Mode().Perm()&0077 != 0) {
		return errors.New("session destination must be a private regular file")
	}
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".cpag-session-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func loadSession(path, origin string) (string, error) {
	f, e := os.Lstat(path)
	if e != nil {
		return "", e
	}
	if !f.Mode().IsRegular() || f.Mode().Perm()&0077 != 0 {
		return "", errors.New("session file must be regular and mode 0600")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	var s storedSession
	if e = json.Unmarshal(b, &s); e != nil {
		return "", e
	}
	if s.Origin != origin || !strings.HasPrefix(s.Cookie, "cpag_session=") {
		return "", errors.New("session belongs to another origin or is invalid")
	}
	return s.Cookie, nil
}
func run(args []string, in io.Reader, out io.Writer) error {
	flags := flag.NewFlagSet("cpagctl", flag.ContinueOnError)
	base := flags.String("url", "http://127.0.0.1:8095", "explicit local application origin")
	session := flags.String("session", ".cpag-session.json", "private user-session file")
	bodyFile := flags.String("body", "", "JSON file; default request body is stdin for POST/PUT")
	upload := flags.String("upload", "", "raw upload file; sets digest and length")
	key := flags.String("idempotency-key", "", "upload request identity")
	if e := flags.Parse(args); e != nil {
		return e
	}
	parts := flags.Args()
	if len(parts) < 1 {
		return errors.New("usage: cpagctl [flags] login | logout | request METHOD /api/v3/path")
	}
	origin, e := localOrigin(*base)
	if e != nil {
		return e
	}
	method, path := "", ""
	switch parts[0] {
	case "login":
		method, path = "POST", "/api/v3/session"
	case "logout":
		method, path = "DELETE", "/api/v3/session"
	case "request":
		if len(parts) != 3 {
			return errors.New("request requires METHOD and /api/v3/path")
		}
		method, path = strings.ToUpper(parts[1]), parts[2]
	default:
		return errors.New("unknown command")
	}
	if !strings.HasPrefix(path, "/api/v3/") || strings.ContainsAny(path, "\r\n") {
		return errors.New("only public /api/v3 routes are allowed")
	}
	parsed, e := url.Parse(path)
	if e != nil || parsed.Host != "" || strings.Contains(parsed.Path, "..") || strings.Contains(parsed.Path, "\\") {
		return errors.New("invalid public API path")
	}
	var body []byte
	if *upload != "" {
		var f *os.File
		f, e = os.Open(*upload)
		if e == nil {
			body, e = io.ReadAll(io.LimitReader(f, (16<<20)+1))
			f.Close()
		}
	} else if *bodyFile != "" {
		body, e = os.ReadFile(*bodyFile)
	} else if method == "POST" || method == "PUT" {
		body, e = io.ReadAll(io.LimitReader(in, 1<<20))
	}
	if e != nil {
		return e
	}
	if len(body) > 16<<20 {
		return errors.New("client upload bound is 16 MiB")
	}
	req, e := http.NewRequest(method, origin+path, bytes.NewReader(body))
	if e != nil {
		return e
	}
	if *upload != "" {
		sum := sha256.Sum256(body)
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("X-Content-SHA256", hex.EncodeToString(sum[:]))
		req.Header.Set("Idempotency-Key", *key)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
	if parts[0] != "login" {
		cookie, e := loadSession(*session, origin)
		if e != nil {
			return e
		}
		req.Header.Set("Cookie", cookie)
	}
	client := http.Client{Timeout: 120 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if e != nil {
		return e
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if parts[0] == "login" {
			cookie := ""
			for _, c := range response.Cookies() {
				if c.Name == "cpag_session" {
					cookie = c.Name + "=" + c.Value
				}
			}
			if cookie == "" {
				return errors.New("successful login lacks a user session")
			}
			if e = saveSession(*session, storedSession{cookie, origin}); e != nil {
				return e
			}
		}
		if parts[0] == "logout" {
			if e = os.Remove(*session); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	if _, e = out.Write(raw); e != nil {
		return e
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		fmt.Fprintln(out)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return nil
}
func main() {
	if e := run(os.Args[1:], os.Stdin, os.Stdout); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
