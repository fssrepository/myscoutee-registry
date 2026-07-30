// Package buildinfo exposes immutable metadata embedded in registry binaries.
package buildinfo

// Version is overridden for release builds with:
//
//	-ldflags "-X github.com/fssrepository/myscoutee-registry/internal/buildinfo.Version=<version>"
//
// The safe development default makes an unversioned binary explicit.
var Version = "dev"

const Service = "myscoutee-registry"
