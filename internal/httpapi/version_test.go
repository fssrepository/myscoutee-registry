package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/buildinfo"
	"github.com/fssrepository/myscoutee-registry/internal/httpapi"
	"github.com/fssrepository/myscoutee-registry/internal/protocol"
)

func TestVersionEndpointIsConfigFreeReadOnlyAndUncacheable(t *testing.T) {
	handler := httpapi.New(nil, httpapi.Options{})
	request := httptest.NewRequest(http.MethodGet, "http://registry.test/versionz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("/versionz status = %d, body = %s", response.Code, response.Body.String())
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("/versionz Content-Type = %q", got)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("/versionz Cache-Control = %q", got)
	}
	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("/versionz X-Content-Type-Options = %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /versionz: %v", err)
	}
	expected := map[string]any{
		"service":          buildinfo.Service,
		"version":          buildinfo.Version,
		"protocol_version": protocol.Version,
	}
	if !reflect.DeepEqual(body, expected) {
		t.Fatalf("/versionz body = %#v, want %#v", body, expected)
	}

	post := httptest.NewRecorder()
	handler.ServeHTTP(
		post,
		httptest.NewRequest(http.MethodPost, "http://registry.test/versionz", nil),
	)
	if post.Code != http.StatusMethodNotAllowed ||
		post.Header().Get("Allow") != http.MethodGet ||
		post.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf(
			"POST /versionz status=%d Allow=%q Cache-Control=%q",
			post.Code,
			post.Header().Get("Allow"),
			post.Header().Get("Cache-Control"),
		)
	}
}

func TestVersionIdentityAndHealthRejectNonCanonicalQueriesWithoutCaching(t *testing.T) {
	handler := httpapi.New(nil, httpapi.Options{})
	for _, path := range []string{"/versionz", protocol.IdentityPath, "/healthz"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(
			response,
			httptest.NewRequest(http.MethodGet, "http://registry.test"+path+"?unexpected=1", nil),
		)
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s query status = %d", path, response.Code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s query Cache-Control = %q", path, response.Header().Get("Cache-Control"))
		}
	}
}
