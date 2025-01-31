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

		client := getNTLMClientForHost(req.URL.Host, ctx.Proxy.Tr, auth)
		fmt.Println("[NTLM] Client =", client)
		var resp *http.Response
		var err error

		newReq := req.Clone(req.Context())
		newReq.RequestURI = ""             // Prevent RequestURI error
		newReq.URL.Host = req.URL.Host     // Ensure request keeps the correct Host
		newReq.URL.Scheme = req.URL.Scheme // Ensure the request keeps the correct Scheme
		resp, err = client.Transport.RoundTrip(newReq)

		if err != nil {
			fmt.Printf("[NTLM] Initial request failed: %v\n", err)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "NTLM Authentication Failed")
		}

		// If server responds with 401 and NTLM authentication is required
		if resp.StatusCode == http.StatusUnauthorized && isNTLMRequired(resp) {
			log.Printf("[NTLM] Server requires NTLM authentication for %s", req.URL.Host)

			// Retry authentication with NTLM
			for attempt := 0; attempt < auth.MaxRetries; attempt++ {
				log.Printf("[NTLM] Attempt %d/%d for %s", attempt+1, auth.MaxRetries, req.URL.Host)

				// Reinitialize client for retry
				client = getNTLMClientForHost(req.URL.Host, ctx.Proxy.Tr, auth)

				// Resend request with NTLM headers
				resp, err = client.Transport.RoundTrip(newReq)
				if err != nil {
					log.Printf("[NTLM] NTLM authentication attempt failed: %v", err)
					continue
				}

				// If authentication succeeds, return response
				if resp.StatusCode != http.StatusUnauthorized {
					log.Printf("[NTLM] Authentication successful for %s", req.URL.Host)
					return req, resp
				}

				log.Printf("[NTLM] Authentication failed, retrying...")
			}

			// If all attempts fail, return the last response
			log.Printf("[NTLM] Authentication failed after %d attempts for %s", auth.MaxRetries, req.URL.Host)
			return req, resp
		}

		// If authentication isn't required, return the response
		return req, resp
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

// isNTLMRequired checks if NTLM authentication is required by the server response.
func isNTLMRequired(resp *http.Response) bool {
	fmt.Println("[NTLM] Checking for NTLM headers in response")
	for _, header := range resp.Header["Www-Authenticate"] {
		if strings.Contains(strings.ToUpper(header), "NTLM") {
			fmt.Println("[NTLM] Server requested NTLM authentication")
			return true
		}
	}
	return false
}
