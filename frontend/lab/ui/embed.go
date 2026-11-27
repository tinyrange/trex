// Package ui embeds the Virtual Lab Editor browser client.
package ui

import "embed"

// Files holds the editor and its browser dependencies.
//
//go:embed index.html style.css app.js vendor
var Files embed.FS
