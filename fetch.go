package portier

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const defaultMaxAge = time.Minute
const defaultErrMaxAge = time.Duration(3) * time.Second

var maxAgeRe = regexp.MustCompile(`max-age\s*=\s*(\d+)`)

// SimpleFetch is a simple http.Client.Get wrapper that also decodes the JSON
// response and parses the Cache-Control header. The returned Duration is the
// cache lifespan for storing the result.
//
// This is the default implementation for cache misses in Store.Fetch.
func SimpleFetch(client *http.Client, url string, data interface{}) (time.Duration, error) {
	maxAge := defaultErrMaxAge

	res, err := client.Get(url)
	if err != nil {
		return maxAge, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return maxAge, fmt.Errorf("unexpected HTTP status: %s", res.Status)
	}

	err = json.NewDecoder(res.Body).Decode(data)
	if err != nil {
		return maxAge, err
	}

	maxAge = defaultMaxAge

	match := maxAgeRe.FindStringSubmatch(res.Header.Get("Cache-Control"))
	if match != nil {
		maxAgeInt, err := strconv.ParseInt(match[1], 10, 64)
		if err == nil {
			maxAgeParsed := time.Duration(maxAgeInt) * time.Second
			if maxAgeParsed > maxAge {
				maxAge = maxAgeParsed
			}
		}
	}

	return maxAge, err
}
