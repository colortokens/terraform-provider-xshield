package cloudauth

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// credentialHTTPClient is client for a cloud's token endpoints, except that the instance metadata, container and
// managed identity endpoints on the machine's own network are never reached through a proxy: a proxy cannot
// reach them, and proxy_url would otherwise send every request to it.
func credentialHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		return &http.Client{Transport: &http.Transport{Proxy: withoutProxyForLocalEndpoints(http.ProxyFromEnvironment)}}
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy == nil {
		return client
	}
	direct := transport.Clone()
	direct.Proxy = withoutProxyForLocalEndpoints(transport.Proxy)
	withDirect := *client
	withDirect.Transport = direct
	return &withDirect
}

func withoutProxyForLocalEndpoints(proxy func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if isLocalEndpoint(req.URL.Hostname()) {
			return nil, nil
		}
		return proxy(req)
	}
}

func isLocalEndpoint(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.EqualFold(host, "metadata.google.internal") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr == netip.MustParseAddr("fd00:ec2::254")
}
