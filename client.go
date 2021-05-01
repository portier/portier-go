package portier

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

// Valid Config.ResponseMode values.
const (
	ResponseModeFormPost = "form_post"
	ResponseModeFragment = "fragment"
)

// Defaults for Config fields.
const (
	DefaultBroker       = "https://broker.portier.io"
	DefaultResponseMode = ResponseModeFormPost
	DefaultLeeway       = time.Duration(3) * time.Minute
	DefaultHTTPTimeout  = time.Duration(10) * time.Second
)

const discoveryPath = "/.well-known/openid-configuration"

// Config is used with NewClient to construct a Client.
//
// The only required field is RedirectURI, which must be set to a route in your
// application that calls Client.Verify. For other fields, NewClient will fall
// back to defaults if they are zero.
type Config struct {
	Store        Store
	Broker       string        // Origin of the broker to use
	RedirectURI  string        // Absolute URL to an app route that calls Verify
	ResponseMode string        // How to call RedirectURI: form_post or fragment
	Leeway       time.Duration // Time offset to allow when validating JWT claims
}

// Client is used to perform Portier authentication.
//
// Whether a Client is safe for concurrent use by multiple goroutines depends
// on the Store used. The store is specified in Config in the call to
// NewClient. If no Store is specified, an in-memory store is created, which is
// safe for concurrent use.
type Client interface {
	// StartAuth creates a login session for the given email, and returns a URL
	// to redirect the user agent (browser) to so authentication can continue.
	//
	// If performing the redirect in the HTTP response, the recommended method is
	// to send a 303 HTTP status code with the Location header set to the URL.
	// But other solutions are possible, such as fetching this URL using a
	// request from client-side JavaScript.
	StartAuth(email string) (string, error)

	// Verify takes an id_token and returns a verified email address.
	//
	// The id_token is delivered to the RedirectURI directly by the user agent
	// (browser). It is sent either via a HTTP POST with a form body, or in the
	// URL fragment, depending on Config.ResponseMode. (In the latter case,
	// additional client-side JavaScript is needed, because the URL fragment is
	// not sent to the server.) The default is HTTP POST.
	Verify(tokenStr string) (string, error)
}

type client struct {
	store        Store
	broker       string
	brokerURL    *url.URL
	redirectURI  string
	clientID     string
	responseMode string
	leeway       time.Duration
}

type prepResult struct {
	clientID  string
	discovery *discoveryDoc
}

// NewClient constructs a Client from a Config.
func NewClient(cfg *Config) (Client, error) {
	client := &client{
		store:        cfg.Store,
		broker:       cfg.Broker,
		redirectURI:  cfg.RedirectURI,
		responseMode: cfg.ResponseMode,
		leeway:       cfg.Leeway,
	}

	if client.store == nil {
		client.store = NewMemoryStore(&http.Client{Timeout: DefaultHTTPTimeout})
	}
	if client.broker == "" {
		client.broker = DefaultBroker
	}
	if client.responseMode == "" {
		client.responseMode = ResponseModeFormPost
	}
	if client.leeway == 0 {
		client.leeway = DefaultLeeway
	}

	if client.redirectURI == "" {
		return nil, fmt.Errorf("RedirectURI not set")
	}
	switch client.responseMode {
	case ResponseModeFormPost:
	case ResponseModeFragment:
		break
	default:
		return nil, fmt.Errorf("invalid ResponseMode: %s", client.responseMode)
	}

	brokerURL, err := url.Parse(client.broker)
	if err != nil {
		return nil, fmt.Errorf("invalid broker: %s", err.Error())
	}
	if !isOrigin(brokerURL) {
		return nil, fmt.Errorf("invalid broker: URL is not an HTTP(S) origin")
	}
	client.brokerURL = brokerURL

	redirectURI, err := url.Parse(client.redirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect URI: %s", err.Error())
	}
	if !redirectURI.IsAbs() {
		return nil, fmt.Errorf("invalid redirect URI: must be absolute")
	}
	client.clientID = originOf(redirectURI)

	return client, nil
}

func (client *client) fetchDiscovery() (*discoveryDoc, error) {
	discovery := &discoveryDoc{}
	discoveryURL := *client.brokerURL
	discoveryURL.Path = discoveryPath
	if err := client.store.Fetch(discoveryURL.String(), &discovery); err != nil {
		return nil, fmt.Errorf("could not fetch discovery document: %s", err.Error())
	}

	return discovery, nil
}

func (client *client) StartAuth(email string) (string, error) {
	discovery, err := client.fetchDiscovery()
	if err != nil {
		return "", err
	}

	authURL, err := url.Parse(discovery.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization_endpoint: %s", err.Error())
	}

	nonce, err := client.store.NewNonce(email)
	if err != nil {
		return "", fmt.Errorf("NewNonce error: %s", err.Error())
	}

	q := make(url.Values)
	q.Set("login_hint", email)
	q.Set("scope", "openid email")
	q.Set("nonce", nonce)
	q.Set("response_type", "id_token")
	q.Set("response_mode", client.responseMode)
	q.Set("client_id", client.clientID)
	q.Set("redirect_uri", client.redirectURI)
	authURL.RawQuery = q.Encode()
	return authURL.String(), nil
}

func (client *client) Verify(tokenStr string) (string, error) {
	discovery, err := client.fetchDiscovery()
	if err != nil {
		return "", err
	}

	keySet := jwk.NewSet()
	if err := client.store.Fetch(discovery.JWKsURI, &keySet); err != nil {
		return "", fmt.Errorf("FetchKeys error: %s", err.Error())
	}

	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKeySet(keySet),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(client.leeway),
		jwt.WithIssuer(client.broker),
		jwt.WithAudience(client.clientID),
	)
	if err != nil {
		return "", fmt.Errorf("jwt.Parse error: %s", err.Error())
	}

	nonceVal, _ := token.Get("nonce")
	nonce, _ := nonceVal.(string)
	if nonce == "" {
		return "", fmt.Errorf("nonce claim missing")
	}

	emailVal, _ := token.Get("email")
	email, _ := emailVal.(string)
	if email == "" {
		return "", fmt.Errorf("email claim missing")
	}

	emailOrigVal, _ := token.Get("email_original")
	emailOrig, _ := emailOrigVal.(string)
	if emailOrig == "" {
		emailOrig = email
	}

	if err := client.store.ConsumeNonce(nonce, emailOrig); err != nil {
		if _, ok := err.(*InvalidNonce); ok {
			return "", fmt.Errorf("invalid session")
		}
		return "", fmt.Errorf("ConsumeNonce error: %s", err.Error())
	}

	return email, nil
}
