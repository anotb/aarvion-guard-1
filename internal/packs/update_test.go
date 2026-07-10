package packs

import "flag"

// update regenerates on-disk snapshots (examples/packs) instead of comparing
// against them: `go test ./internal/packs/ -run Snapshot -update`.
var update = flag.Bool("update", false, "regenerate examples/packs snapshot files")
