package version

// These are overridable at build time via -ldflags.
var (
	Version = "0.1.0"
	Commit  = "dev"
	Date    = "unknown"
)

// Info returns the full version string.
func Info() string {
	return "GFW X " + Version + " (" + Commit + ", " + Date + ")"
}

// Short returns just the semantic version.
func Short() string {
	return Version
}
