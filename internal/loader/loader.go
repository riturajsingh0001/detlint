// Package loader walks a directory tree and parses rule files concurrently.
package loader

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/riturajsingh0001/detlint/internal/rule"
)

// Options controls loading.
type Options struct {
	// Changed, when non-empty, restricts loading to these paths. Keys may be
	// absolute or relative to the current directory.
	Changed map[string]bool
}

// FileError records a rule file that failed to parse.
type FileError struct {
	Path string
	Err  error
}

// Result is the output of a load.
type Result struct {
	Files  []*rule.File
	Errors []FileError
	Lines  map[string][]string
}

// LoadDir loads rules from a directory or a single file.
func LoadDir(dir string, opts Options) (*Result, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return loadPaths([]string{dir}, opts, func(p string) ([]byte, error) { return os.ReadFile(p) })
	}

	var paths []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			if d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if isRuleFile(p) {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no rule files (*.yml, *.yaml) found under %s", dir)
	}
	return loadPaths(paths, opts, func(p string) ([]byte, error) { return os.ReadFile(p) })
}

// LoadFS loads rules from an fs.FS, used by the embedded demo.
func LoadFS(fsys fs.FS, root string, opts Options) (*Result, error) {
	info, err := fs.Stat(fsys, root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return loadPaths([]string{root}, opts, func(p string) ([]byte, error) { return fs.ReadFile(fsys, p) })
	}
	var paths []string
	err = fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if isRuleFile(p) {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no rule files (*.yml, *.yaml) found under %s", root)
	}
	return loadPaths(paths, opts, func(p string) ([]byte, error) { return fs.ReadFile(fsys, p) })
}

func isRuleFile(p string) bool {
	ext := strings.ToLower(path.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}

func loadPaths(paths []string, opts Options, read func(string) ([]byte, error)) (*Result, error) {
	sort.Strings(paths)
	if len(opts.Changed) > 0 {
		filtered := paths[:0]
		for _, p := range paths {
			if isChanged(opts.Changed, p) {
				filtered = append(filtered, p)
			}
		}
		paths = filtered
		if len(paths) == 0 {
			return &Result{Lines: map[string][]string{}}, nil
		}
	}

	files := make([]*rule.File, len(paths))
	errs := make([]error, len(paths))
	lines := make(map[string][]string, len(paths))
	var mu sync.Mutex

	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	if workers > 16 {
		workers = 16
	}
	if workers > len(paths) {
		workers = len(paths)
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				p := paths[i]
				data, err := read(p)
				if err != nil {
					errs[i] = err
					continue
				}
				f, perr := rule.Parse(p, data)
				if f != nil {
					files[i] = f
					mu.Lock()
					lines[p] = f.Lines
					mu.Unlock()
				}
				if perr != nil {
					errs[i] = perr
				}
			}
		}()
	}
	for i := range paths {
		next <- i
	}
	close(next)
	wg.Wait()

	res := &Result{Lines: lines}
	for i, f := range files {
		if f != nil {
			res.Files = append(res.Files, f)
		}
		if errs[i] != nil {
			res.Errors = append(res.Errors, FileError{Path: paths[i], Err: errs[i]})
		}
	}
	return res, nil
}

func isChanged(set map[string]bool, p string) bool {
	cands := []string{filepath.ToSlash(filepath.Clean(p))}
	if abs, err := filepath.Abs(p); err == nil {
		cands = append(cands, filepath.ToSlash(filepath.Clean(abs)))
	}
	for _, c := range cands {
		if set[c] {
			return true
		}
	}
	return false
}
