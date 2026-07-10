package console

import "embed"

// uiFS holds the static console UI, embedded at build time.
//
//go:embed ui/*
var uiFS embed.FS
