package hostaccounts

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// WebPreviewFixtureForTest is compiled only into tests. The healthy fixture is
// empty because Windows hostaccount paths cannot qualify Linux compiler paths.
// Populated native account validation remains separately tested by the compiler.
func WebPreviewFixtureForTest(t *testing.T, factory WebPreviewFactory) (WebPreviewService, func()) {
	t.Helper()
	s, n, _ := setupStore(t)
	handler := handlerWithWebPreview(s, factory(s.SnapshotProvider()))
	c := &client{configured: true, http: &http.Client{Transport: previewRoundTrip(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Result(), nil
	})}}
	drift := func() { createFixture(t, s); n.changed = true }
	return c, drift
}
