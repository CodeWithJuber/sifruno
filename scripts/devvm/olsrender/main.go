// Command olsrender renders OpenLiteSpeed configuration from a JSON site spec
// with internal/olsweb, the same code a reconciler will call, and writes the
// files under an output directory using their paths relative to the
// OpenLiteSpeed server root. It prints each path it wrote, one per line.
//
//	olsrender --spec FILE.json --out DIR [--force]
//
// It refuses a non-empty DIR unless --force is given, and it never deletes
// anything. It is a proof tool for the dev VM, not a product command.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"sifruno/internal/olsweb"
)

const maxSpecBytes = 1 << 20

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("olsrender", flag.ContinueOnError)
	flags.SetOutput(stderr)
	specPath := flags.String("spec", "", "JSON site spec (olsweb.Server)")
	outDir := flags.String("out", "", "Directory to write the rendered tree into")
	force := flags.Bool("force", false, "Write into a non-empty directory, replacing same-named files")
	if flags.Parse(args) != nil || *specPath == "" || *outDir == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: olsrender --spec FILE.json --out DIR [--force]")
		return 2
	}
	spec, err := readSpec(*specPath)
	if err != nil {
		fmt.Fprintln(stderr, "olsrender:", err)
		return 1
	}
	files, err := olsweb.Render(spec)
	if err != nil {
		fmt.Fprintln(stderr, "olsrender:", err)
		return 1
	}
	written, err := writeTree(*outDir, files, *force)
	for _, path := range written {
		fmt.Fprintln(stdout, path)
	}
	if err != nil {
		fmt.Fprintln(stderr, "olsrender:", err)
		return 1
	}
	return 0
}

// readSpec decodes exactly one JSON object and refuses unknown fields, so a
// misspelt key fails instead of silently taking a default.
func readSpec(path string) (olsweb.Server, error) {
	f, err := os.Open(path)
	if err != nil {
		return olsweb.Server{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSpecBytes+1))
	if err != nil {
		return olsweb.Server{}, err
	}
	if len(data) > maxSpecBytes {
		return olsweb.Server{}, fmt.Errorf("%s is larger than %d bytes", path, maxSpecBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var spec olsweb.Server
	if err := dec.Decode(&spec); err != nil {
		return olsweb.Server{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return olsweb.Server{}, fmt.Errorf("%s: data after the JSON object", path)
	}
	return spec, nil
}

// writeTree writes files under dir through an os.Root, so a symlink already
// in a forced output directory cannot redirect a write outside it.
func writeTree(dir string, files map[string][]byte, force bool) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > 0 && !force {
		return nil, fmt.Errorf("%s is not empty; use --force to write into it", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var written []string
	for _, path := range paths {
		if !filepath.IsLocal(path) {
			return written, fmt.Errorf("refusing non-local path %q", path)
		}
		if err := root.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return written, err
		}
		if err := root.WriteFile(path, files[path], 0o644); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}
