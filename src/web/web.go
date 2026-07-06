// Package web holds the embedded static assets for the keephippo web console
// (served at /ui) and the application icon set. The UI is plain HTML/CSS/JS with
// no build step — it is just another client of the /v1/* API.
package web

import "embed"

// Assets is the embedded web console: index.html, app.css, app.js, and the icon
// set under icons/.
//
//go:embed index.html app.css app.js icons
var Assets embed.FS
