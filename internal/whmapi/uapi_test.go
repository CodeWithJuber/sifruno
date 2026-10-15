package whmapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// UAPI goldens from licensed 138 captures (batch 3 + batch 7).

func uapiCall(t *testing.T, s *Server, token, path string) map[string]any {
	t.Helper()
	w := post(t, s, path, token)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	return body
}

func uapiResultOf(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	res, ok := body["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", body)
	}
	return res
}

func TestUAPIEnvelopeShape(t *testing.T) {
	s, token := newLifecycleServer(t, &fakeHost{accounts: nil})
	body := uapiCall(t, s, token, "/execute/ServerInformation/get_information?api.version=3")
	// Envelope keys observed on the reference.
	if body["apiversion"].(float64) != 3 || body["module"] != "ServerInformation" || body["func"] != "get_information" {
		t.Fatalf("envelope = %v", body)
	}
	res := uapiResultOf(t, body)
	for _, k := range []string{"data", "errors", "warnings", "status", "messages", "metadata"} {
		if _, present := res[k]; !present {
			t.Fatalf("result missing observed key %s: %v", k, res)
		}
	}
	// status (not result) is the success flag.
	if res["status"].(float64) != 1 {
		t.Fatalf("status = %v", res["status"])
	}
}

func TestUAPIListDomainsTruthful(t *testing.T) {
	h := &fakeHost{}
	s, token := newLifecycleServer(t, h)
	post(t, s, "/json-api/createacct?api.version=1&username=domuser&domain=dom.example.com", token)
	body := uapiCall(t, s, token, "/execute/DomainInfo/list_domains?api.version=3&user=domuser")
	res := uapiResultOf(t, body)
	data := res["data"].(map[string]any)
	if data["main_domain"] != "dom.example.com" {
		t.Fatalf("data = %v", data)
	}
	for _, k := range []string{"parked_domains", "sub_domains", "addon_domains"} {
		arr, ok := data[k].([]any)
		if !ok || len(arr) != 0 {
			t.Fatalf("%s must be an empty array: %v", k, data[k])
		}
	}
}

func TestUAPIPrimaryAndSingleDomain(t *testing.T) {
	h := &fakeHost{}
	s, token := newLifecycleServer(t, h)
	post(t, s, "/json-api/createacct?api.version=1&username=domuser&domain=dom.example.com", token)
	body := uapiCall(t, s, token, "/execute/DomainInfo/primary_domain?api.version=3&user=domuser")
	if uapiResultOf(t, body)["data"].(map[string]any)["primary_domain"] != "dom.example.com" {
		t.Fatalf("body = %v", body)
	}
	body = uapiCall(t, s, token, "/execute/DomainInfo/single_domain_data?api.version=3&user=domuser&domain=dom.example.com")
	data := uapiResultOf(t, body)["data"].(map[string]any)
	if data["documentroot"] != "/home/domuser/public_html" || data["type"] != "main_domain" || data["servername"] != "dom.example.com" {
		t.Fatalf("data = %v", data)
	}
	// Unknown domain on the account: clean error envelope.
	body = uapiCall(t, s, token, "/execute/DomainInfo/single_domain_data?api.version=3&user=domuser&domain=other.example.com")
	res := uapiResultOf(t, body)
	if res["status"].(float64) != 0 {
		t.Fatalf("unknown domain status = %v", res["status"])
	}
}

func TestUAPIServerInformationTruthful(t *testing.T) {
	s, token := newLifecycleServer(t, &fakeHost{})
	body := uapiCall(t, s, token, "/execute/ServerInformation/get_information?api.version=3")
	res := uapiResultOf(t, body)
	data, ok := res["data"].([]any)
	if !ok || len(data) == 0 {
		t.Fatalf("data = %v", res["data"])
	}
	// Only services sifruno actually runs; no cPanel daemon names claimed.
	joined, _ := json.Marshal(data)
	for _, fake := range []string{"cpsrvd", "exim", "dovecot", "httpd"} {
		if strings.Contains(string(joined), `"`+fake+`"`) {
			t.Fatalf("fabricated service %s in %s", fake, joined)
		}
	}
}

func TestUAPIUnknownModuleAndFunc(t *testing.T) {
	s, token := newLifecycleServer(t, &fakeHost{})
	body := uapiCall(t, s, token, "/execute/NoSuchMod/no_such?api.version=3")
	res := uapiResultOf(t, body)
	if res["status"].(float64) != 0 {
		t.Fatalf("unknown module status = %v", res)
	}
	errs, ok := res["errors"].([]any)
	if !ok || len(errs) != 1 || !strings.Contains(errs[0].(string), "Cpanel::API::NoSuchMod") {
		t.Fatalf("errors = %v", res["errors"])
	}
	body = uapiCall(t, s, token, "/execute/DomainInfo/no_such_func?api.version=3")
	if uapiResultOf(t, body)["status"].(float64) != 0 {
		t.Fatal("unknown func must fail")
	}
}

func TestUAPIAuthAndScoping(t *testing.T) {
	s2, token2 := newLifecycleServer(t, &fakeHost{})
	// No auth: denied with the legacy envelope.
	r := httptest.NewRequest(http.MethodGet, "/execute/DomainInfo/list_domains?api.version=3&user=x", nil)
	w := httptest.NewRecorder()
	s2.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("no-auth status = %d", w.Code)
	}
	// Account-scoped call without user: exact required-param error.
	body := uapiCall(t, s2, token2, "/execute/DomainInfo/list_domains?api.version=3")
	res := uapiResultOf(t, body)
	if res["status"].(float64) != 0 || !strings.Contains(res["errors"].([]any)[0].(string), "parameter is required") {
		t.Fatalf("missing-user errors = %v", res["errors"])
	}
	// Unknown account.
	body = uapiCall(t, s2, token2, "/execute/DomainInfo/list_domains?api.version=3&user=ghost")
	res = uapiResultOf(t, body)
	if res["status"].(float64) != 0 || !strings.Contains(res["errors"].([]any)[0].(string), "does not exist") {
		t.Fatalf("ghost errors = %v", res["errors"])
	}
}
