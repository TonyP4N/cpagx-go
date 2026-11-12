package catalog

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Configure the serialized origin sent by the browser, independently of all proxy headers.
func validateExternalOrigin(origin string) error {
	if origin == "" {
		return nil
	}
	invalid := errors.New("external_origin must be a canonical HTTPS or loopback HTTP origin without a path")
	u, err := url.Parse(origin)
	if err != nil || u.User != nil || origin != u.Scheme+"://"+u.Host || len(u.Hostname()) > 253 {
		return invalid
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "127.0.0.1") {
		return invalid
	}
	for _, label := range strings.Split(u.Hostname(), ".") {
		if !dnsLabel.MatchString(label) {
			return invalid
		}
	}
	expectedHost := u.Hostname()
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || (u.Scheme == "https" && n == 443) || (u.Scheme == "http" && n == 80) || strconv.Itoa(n) != port {
			return invalid
		}
		expectedHost += ":" + port
	}
	if u.Host != expectedHost {
		return invalid
	}
	return nil
}

func (c Config) allowsWrite(r *http.Request) bool {
	if c.ExternalOrigin != "" && (len(r.Header.Values("Forwarded")) > 0 ||
		len(r.Header.Values("X-Forwarded-Host")) > 0 || len(r.Header.Values("X-Forwarded-Proto")) > 0) {
		return false
	}
	origins := r.Header.Values("Origin")
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	expected := c.ExternalOrigin
	if expected == "" {
		expected = "http://" + c.PublicAddr
	}
	if len(origins) != 0 {
		return len(origins) == 1 && origins[0] == expected
	}
	// Keep non-browser CLI requests working. Forwarding headers cannot take
	// the place of an Origin on writes to the external entry.
	return c.ExternalOrigin == "" || r.Header.Get("Sec-Fetch-Site") == ""
}
