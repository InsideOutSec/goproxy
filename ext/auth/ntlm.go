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

// NTLMAuth stores credentials and retry settings
type NTLMAuth struct {
	Domain     string
	Username   string
	Password   string
	MaxRetries int
}

// Cache NTLM-capable HTTP clients per host
var ntlmClientCache sync.Map

// NTLMAuthMiddleware applies NTLM authentication
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

		// Create a clean outbound request
		outReq, err := createOutboundRequest(req)
		if err != nil {
			log.Printf("[NTLM] Error creating outbound request: %v", err)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "NTLM Authentication Failed")
		}

		client := getNTLMClientForHost(req.URL.Host, ctx.Proxy.Tr, auth)

		// First attempt: Send request normally and check if NTLM is required
		resp, err := client.Transport.RoundTrip(outReq)
		if err != nil {
			fmt.Printf("[NTLM] Initial request failed: %v\n", err)
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "NTLM Authentication Failed")
		}

		// If server responds with 401 and requires NTLM authentication
		if resp.StatusCode == http.StatusUnauthorized && isNTLMRequired(resp) {
			log.Printf("[NTLM] Server requires NTLM authentication for %s", req.URL.Host)

			// Retry authentication with NTLM
			for attempt := 0; attempt < auth.MaxRetries; attempt++ {
				log.Printf("[NTLM] Attempt %d/%d for %s", attempt+1, auth.MaxRetries, req.URL.Host)

				// Reinitialize client for retry
				client = getNTLMClientForHost(req.URL.Host, ctx.Proxy.Tr, auth)

				// Recreate outbound request for retry
				outReq, err = createOutboundRequest(req)
				if err != nil {
					log.Printf("[NTLM] Error creating outbound request on retry: %v", err)
					return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusProxyAuthRequired, "NTLM Authentication Failed")
				}

				resp, err = client.Transport.RoundTrip(outReq)
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

// getNTLMClientForHost returns a cached *http.Client with NTLM authentication
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
		RoundTripper: base,
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
	for _, header := range resp.Header["Www-Authenticate"] {
		if strings.Contains(strings.ToUpper(header), "NTLM") {
			fmt.Println("[NTLM] Server requested NTLM authentication")
			return true
		}
	}
	return false
}

// createOutboundRequest ensures the request is properly formatted for NTLM authentication.
func createOutboundRequest(req *http.Request) (*http.Request, error) {
	outReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
	if err != nil {
		return nil, fmt.Errorf("[NTLM] Error creating outbound request: %w", err)
	}

	// Copy headers, Host, and ensure RequestURI is empty
	outReq.Header = req.Header.Clone()
	outReq.Host = req.Host
	outReq.RequestURI = "" // MUST be empty for Go http.Client

	return outReq, nil
}
