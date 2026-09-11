// Package web embeds the built management UI (a single inlined index.html)
// and serves it as a CPA plugin resource under
// /v0/resource/plugins/cpa-key-policy/index.html.
//
// dist/index.html is a build artifact produced by `npm run build` in ../../web.
// A placeholder is committed so the Go build never fails when the frontend has
// not been built yet; the real UI replaces it after a frontend build.
package web

import (
	_ "embed"
	"net/http"
	"strings"
)

//go:embed dist/index.html
var indexHTML []byte

const contentType = "text/html; charset=utf-8"

// IndexPath is the resource path (relative to the plugin resource base) the UI
// is served at.
const IndexPath = "/index.html"
const LookupPath = "/lookup"
const LookupDataPath = "/lookup/data"

// Serve returns a management response for a plugin resource GET request. It
// only handles the index page; any other path yields 404.
func Serve(path string) (status int, headers http.Header, body []byte) {
	path = strings.TrimRight(path, "/")
	if path != IndexPath && path != LookupPath {
		return http.StatusNotFound, http.Header{"Content-Type": []string{"text/plain; charset=utf-8"}}, []byte("not found")
	}
	return http.StatusOK, http.Header{
		"Content-Type":           []string{contentType},
		"Cache-Control":          []string{"no-store"},
		"X-Content-Type-Options": []string{"nosniff"},
	}, indexHTML
}
