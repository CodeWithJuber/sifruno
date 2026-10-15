package whmapi

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/gofrs/flock"
)

// OpenTokenStore loads a root-only JSON token file (map user -> token).
// A missing file yields an empty store that denies every credential —
// the surface fails closed until an operator issues tokens. Token issuance
// and rotation land with the pr-access credential batch; operators create
// the file manually (mode 0600) for now.
func OpenTokenStore(path string) (TokenStore, error) {
	if path == "" {
		return nil, errors.New("whmapi: token store path required")
	}
	lock := flock.New(path + ".lock")
	lock.Lock() //nolint:errcheck // read-only load; contention simply waits
	defer lock.Unlock()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return TokenStore{}, nil
	}
	if err != nil {
		return nil, err
	}
	store := TokenStore{}
	if err := json.Unmarshal(raw, &store); err != nil {
		return nil, err
	}
	for user, token := range store {
		if user == "" || token == "" {
			return nil, errors.New("whmapi: token store entries require non-empty user and token")
		}
	}
	return store, nil
}
