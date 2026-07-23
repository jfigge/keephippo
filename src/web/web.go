// Package web holds the embedded static assets for the keephippo web console
// (served at /ui) and the application icon set. The UI is plain HTML/CSS/JS with
// no build step — it is just another client of the /v1/* API.
package web

import (
	"embed"
	"io/fs"
)

// Assets is the embedded web console: index.html, app.css, app.js, and the icon
// set under icons/.
//
//go:embed index.html app.css app.js icons
var Assets embed.FS

// swaggerAssets holds the embedded Swagger UI bundle and the OpenAPI 3.0 spec
// (openapi.yaml). The Swagger UI files are vendored third-party assets under the
// Apache-2.0 license (see swagger/LICENSE and swagger/NOTICE); openapi.yaml is
// the hand-maintained description of the /v1/* API.
//
//go:embed swagger
var swaggerAssets embed.FS

// Swagger returns the embedded Swagger UI assets rooted at the swagger/
// directory, so index.html and openapi.yaml sit at the filesystem root. It is
// served at /swagger.
func Swagger() fs.FS {
	sub, err := fs.Sub(swaggerAssets, "swagger")
	if err != nil {
		// The embedded path is a compile-time constant, so this cannot fail.
		panic(err)
	}
	return sub
}
