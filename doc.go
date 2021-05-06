// Package portier implements a client for the Portier protocol.
//
// The primary interface of this package is the Client, created via NewClient.
//
// Some data storage is needed to implement the protocol. This is used for
// tracking short-lived login sessions, and caching of basic HTTP GET requests.
// The Store interface facilitates this, and by default, an in-memory store is
// used. This will work fine for simple single-process applications, but if you
// intend to run multiple workers, an alternative Store must be implemented.
// (In the future, we may offer some alternatives for common databases.
// Contributions are welcome!)
//
// Some applications may need more than a single Client / Config, for example
// because they serve multiple domains. In this case, we recommended creating
// short-lived Clients and sharing the Store between them.
package portier
