// Command mkzip writes a byte-for-byte reproducible zip archive: entries
// in name order, every timestamp SOURCE_DATE_EPOCH, every mode 0755, and
// nothing taken from the build machine (owner, local time, umask). It
// builds the issuer's function archive, which
// deployments pin by SHA-256 (CALLING-SERVICE §8.2).
//
//	mkzip -o out.zip [-mtime <unix seconds>] <file>=<name in archive> [...]
//
// Every entry is stored with mode 0755 (the archive holds the function's
// "bootstrap" executable).
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	out := flag.String("o", "", "output archive")
	mtime := flag.Int64("mtime", 0, "timestamp of every entry, Unix seconds (SOURCE_DATE_EPOCH)")
	flag.Parse()
	if err := run(*out, *mtime, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "mkzip:", err)
		os.Exit(1)
	}
}

func run(out string, mtime int64, args []string) error {
	if out == "" || len(args) == 0 {
		return fmt.Errorf("usage: mkzip -o out.zip [-mtime secs] file=name [file=name]")
	}
	type entry struct{ src, name string }
	var entries []entry
	for _, a := range args {
		src, name, ok := strings.Cut(a, "=")
		if !ok || src == "" || name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			return fmt.Errorf("bad entry %q", a)
		}
		entries = append(entries, entry{src, name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	// zip stores DOS times; anything before 1980 is clamped by the format.
	ts := time.Unix(mtime, 0).UTC()
	if ts.Year() < 1980 {
		ts = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: ts}
		h.SetMode(fs.FileMode(0o755))
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		r, err := os.Open(e.src)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, r)
		r.Close()
		if err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return f.Close()
}
