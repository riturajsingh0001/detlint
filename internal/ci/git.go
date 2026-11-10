package ci

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// ChangedFiles returns files changed relative to base. With an empty base it
// compares against HEAD and includes untracked files.
func ChangedFiles(base string) (map[string]bool, error) {
	out := map[string]bool{}

	add := func(paths []string) {
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			slash := filepath.ToSlash(filepath.Clean(p))
			out[slash] = true
			if abs, err := filepath.Abs(p); err == nil {
				out[filepath.ToSlash(filepath.Clean(abs))] = true
			}
		}
	}

	args := []string{"diff", "--name-only", "--diff-filter=ACMR"}
	if base != "" {
		args = append(args, base+"...HEAD")
	} else {
		args = append(args, "HEAD")
	}
	diff, err := runGit(args...)
	if err != nil {
		return nil, err
	}
	add(strings.Split(diff, "\n"))

	untracked, err := runGit("ls-files", "--others", "--exclude-standard")
	if err == nil {
		add(strings.Split(untracked, "\n"))
	}
	return out, nil
}

func runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), msg)
	}
	return stdout.String(), nil
}
