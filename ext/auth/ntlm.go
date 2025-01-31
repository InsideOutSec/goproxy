package auth

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/InsideOutSec/goproxy"
	httpntlm "github.com/vadimi/go-http-ntlm/v2"
)

// NTLMAuth holds credentials and retry settings for NTLM authentication
type NTLMAuth struct {
	Domain     string
	Username   string
	Password   string
	MaxRetries int // Number of times to retry authentication if it fails
}

// Cache NTLM-capable HTTP clients per host to reuse sessions
var ntlmClientCache sync.Map

// NTLMAuthMiddleware applies NTLM authentication for proxy requests
func NTLMAuthMiddleware(domain, username, password string, maxRetries int) goproxy.ReqHandler {
	auth := &NTLMAuth{
		Domain:     domain,
		Username:   username,
		Password:   password,
		MaxRetries: maxRetries,
	}
	fmt.Println("[NTLM] Middleware initialized")

	return goproxy.FuncReqHandler(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		fmt.Println("[NTLM] Entering authentication flow")

		// Ensure NTLM is applied if required
		if requiresNTLM(req) {
			fmt.Println("[NTLM] NTLM required, proceed with auth flow")
			client := getNTLMClientForHost(req.URL.Host, ctx.Proxy.Tr, auth)

			var resp *http.Response
			var err error

			// If no Authorization header, force NTLM Negotiate on first request
			if req.Header.Get("Authorization") == "" {
				log.Printf("[NTLM] No NTLM Authorization header found. Sending Negotiate request...")
				req.Header.Set("Authorization", "NTLM") // Force NTLM Negotiate
			}

			// Attempt authentication with retries
			for attempt := 0; attempt <= auth.MaxRetries; attempt++ {
				resp, err = client.Transport.RoundTrip(req)
				if err != nil {
					fmt.Printf("[NTLM] Request failed: %v", err)
					break
				}

				// If authentication is successful, return the response
				if resp.StatusCode != http.StatusUnauthorized {
					fmt.Printf("[NTLM] Authentication successful for %s\n", req.URL.Host)
					return req, resp
				}

				log.Printf("[NTLM] Attempt %d/%d failed for %s, retrying...", attempt+1, auth.MaxRetries, req.URL.Host)

				// If we've reached the retry limit, return the server's last error response
				if attempt == auth.MaxRetries {
					fmt.Printf("[NTLM] Authentication failed after %d attempts for %s\n", auth.MaxRetries, req.URL.Host)
					return req, resp
				}

				// If 401 Unauthorized, restart the NTLM handshake
				req.Header.Set("Authorization", "NTLM")
				client = getNTLMClientForHost(req.URL.Host, ctx.Proxy.Tr, auth)
			}

			// If an error occurred, return a generic 407 Proxy Auth Required response
			if err != nil {
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "NTLM Authentication Failed")
			}

			// Return the last failed response from the server
			return req, resp
		}

		return req, nil
	})
}

// getNTLMClientForHost returns a cached *http.Client with NTLM authentication for the given host.
func getNTLMClientForHost(host string, base http.RoundTripper, auth *NTLMAuth) *http.Client {
	if c, ok := ntlmClientCache.Load(host); ok {
		fmt.Println("[NTLM] Using cached NTLM client for", host)
		return c.(*http.Client)
	}

	fmt.Printf("[NTLM] Creating new NTLM client for %s\n", host)
	ntlmTr := &httpntlm.NtlmTransport{
		Domain:       auth.Domain,
		User:         auth.Username,
		Password:     auth.Password,
		RoundTripper: base, // Use goproxy's transport
	}

	client := &http.Client{
		Transport: ntlmTr,
		Timeout:   0, // Indefinite, allowing session reuse
	}

	ntlmClientCache.Store(host, client)
	return client
}

// requiresNTLM checks if the request requires NTLM authentication.
func requiresNTLM(req *http.Request) bool {
	fmt.Println("[NTLM] Checking if request requires NTLM")
	return strings.Contains(req.Header.Get("Proxy-Authorization"), "NTLM") ||
		strings.Contains(req.Header.Get("Authorization"), "NTLM")
}
