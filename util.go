package portier

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
)

// discoveryDoc is the model used for JSON decoding of the OpenID discovery
// document that lives on the server at `/.well-known/openid-configuration`.
// Fields are limited to what is used by Client.
type discoveryDoc struct {
	JWKsURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

// GenerateNonce returns a hex string of 128-bits secure random data.
//
// This is the default implementation used by a Store.NewNonce to generate
// nonces (numbers used once). This function panics if the RNG fails.
func GenerateNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Fatal("nonce generator error:", err)
	}

	return hex.EncodeToString(buf)
}

// isOrigin checks whether a URL is a valid origin.
func isOrigin(url *url.URL) bool {
	return url.Scheme != "" &&
		url.User == nil &&
		url.Path == "" &&
		url.RawPath == "" &&
		url.ForceQuery == false &&
		url.RawQuery == "" &&
		url.Fragment == "" &&
		url.RawFragment == ""
}

// originOf returns the origin of an absolute URL.
func originOf(url *url.URL) string {
	if url.Opaque != "" {
		return fmt.Sprintf("%s:%s", url.Scheme, url.Opaque)
	}
	return fmt.Sprintf("%s://%s", url.Scheme, url.Host)
}
