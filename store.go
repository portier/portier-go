package portier

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"time"
)

// Store is the backing store used by Client for two purposes:
//
// - to fetch JSON documents using HTTP GET with additional caching, and
//
// - to generate and manage nonces (numbers used once) used in authentication.
//
// Whether a Store (and thus the Client using it) is safe for concurrent use is
// left to the implementation.
type Store interface {
	// Fetch requests a documents using HTTP GET, and additionally performs JSON
	// decoding and caching.
	//
	// Implementors should honor HTTP cache headers, with a sensibile minimum
	// (and possibly maximum) applied to the cache lifespan. See SimpleFetch for
	// a default fallback implementation that can be used on cache miss.
	//
	// The Client calls this method with the data parameter set to a double
	// pointer to a zero value of the type to unmarshal. The double pointer
	// allows the implementor to return a shared copy, discarding the zero value.
	// If no shared copy is available, the implementor can take ownership of the
	// zero value and fill it using json.Unmarshal.
	Fetch(url string, data interface{}) error

	// NewNonce generates a random nonce and stores the pair nonce/email.
	//
	// Most implementations should use the GenerateNonce helper, but are allowed
	// to use a different implementation to better fit the backing store. The
	// returned string should be in some URL safe format to prevent unnecessary
	// escaping.
	//
	// Implementors should not apply any limits to the amount of active nonces;
	// this is left to the application using the Client.
	NewNonce(email string) (string, error)

	// ConsumeNonce deletes the nonce/email pair if it exists, or returns an
	// InvalidNonce error if it does not. Other errors may be returned as needed.
	ConsumeNonce(nonce string, email string) error
}

// InvalidNonce is returned by Store.ConsumeNonce when the nonce/email pair was
// not found in the store.
type InvalidNonce struct{}

func (*InvalidNonce) Error() string {
	return "invalid nonce"
}

type memoryStore struct {
	*http.Client

	cache     map[string]*cacheEntry
	cacheLock sync.Mutex

	nonces     map[string]struct{}
	noncesLock sync.Mutex
}

type cacheEntry struct {
	sync.Mutex
	data    interface{}
	err     error
	expires time.Time
}

// NewMemoryStore creates a Store that keeps everything in-memory. This is the
// default Store implementation if a Client is used without explicitely
// specifying one.
//
// When manually creating a store using this function, it is strongly
// recommended to configure the http.Client with a timeout. (See
// DefaultHTTPTimeout)
//
// The in-memory store is safe for concurrent use by multiple goroutines.
//
// Note that the cache in this store only grows. This is fine, because it is
// assumed the store is only used to periodically refresh a couple of documents
// of the Portier broker.
//
// Note also that the in-memory store will only work as expected if there is
// only one application process.
func NewMemoryStore(httpClient *http.Client) Store {
	return &memoryStore{
		Client: httpClient,
		cache:  make(map[string]*cacheEntry),
		nonces: make(map[string]struct{}),
	}
}

func (store *memoryStore) getCacheEntry(url string) *cacheEntry {
	store.cacheLock.Lock()
	defer store.cacheLock.Unlock()

	if entry, ok := store.cache[url]; ok {
		return entry
	}

	entry := &cacheEntry{}
	store.cache[url] = entry
	return entry
}

func (store *memoryStore) Fetch(url string, data interface{}) error {
	entry := store.getCacheEntry(url)
	entry.Lock()
	defer entry.Unlock()

	if !time.Now().Before(entry.expires) {
		entry.data = reflect.ValueOf(data).Elem().Interface() // take ownership
		maxAge, err := SimpleFetch(store.Client, url, entry.data)
		entry.err = err
		entry.expires = time.Now().Add(maxAge)
	}

	if entry.err == nil {
		ptr := reflect.ValueOf(entry.data)
		reflect.ValueOf(data).Elem().Set(ptr)
	}
	return entry.err
}

func (store *memoryStore) NewNonce(email string) (string, error) {
	nonce := GenerateNonce()
	pair := fmt.Sprintf("%s:%s", nonce, email)

	store.noncesLock.Lock()
	defer store.noncesLock.Unlock()

	store.nonces[pair] = struct{}{}
	return nonce, nil
}

func (store *memoryStore) ConsumeNonce(nonce string, email string) error {
	pair := fmt.Sprintf("%s:%s", nonce, email)

	store.noncesLock.Lock()
	defer store.noncesLock.Unlock()

	if _, ok := store.nonces[pair]; !ok {
		return &InvalidNonce{}
	}

	delete(store.nonces, pair)
	return nil
}
