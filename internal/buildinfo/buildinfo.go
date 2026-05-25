package buildinfo

// These values are intended to be overridden by release builds with -ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

func Current(name string) Info {
	return Info{
		Name:    name,
		Version: Version,
		Commit:  Commit,
		Date:    Date,
	}
}
