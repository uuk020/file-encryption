package internal

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sync/errgroup"
)

// DirResult holds the results of a concurrent directory operation.
type DirResult struct {
	Success []string
	Failed  []string
	Skipped []string
}

// EncryptDirConcurrent encrypts all files in a directory concurrently.
// It skips files that already have the .xu extension (recorded in Skipped).
// The workers parameter controls the maximum number of concurrent goroutines.
// If workers <= 0, it defaults to runtime.NumCPU().
func EncryptDirConcurrent(dir string, password string, workers int) (*DirResult, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	var files []string
	var skipped []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".xu") {
			skipped = append(skipped, path)
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	type fileResult struct {
		path string
		err  error
	}
	results := make([]fileResult, len(files))

	g := new(errgroup.Group)
	g.SetLimit(workers)

	for i, file := range files {
		i, file := i, file
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					results[i] = fileResult{path: file, err: fmt.Errorf("panic: %v", r)}
				}
			}()
			results[i] = fileResult{path: file, err: EncryptFileNew(file, password)}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	result := &DirResult{Skipped: skipped}
	for _, r := range results {
		if r.err != nil {
			result.Failed = append(result.Failed, r.path)
		} else {
			result.Success = append(result.Success, r.path)
		}
	}

	return result, nil
}

// DecryptDirConcurrent decrypts all .xu files in a directory concurrently.
// It only processes files with the .xu extension; other files are recorded in Skipped.
// The workers parameter controls the maximum number of concurrent goroutines.
// If workers <= 0, it defaults to runtime.NumCPU().
func DecryptDirConcurrent(dir string, password string, workers int) (*DirResult, error) {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	var files []string
	var skipped []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".xu") {
			skipped = append(skipped, path)
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}

	type fileResult struct {
		path string
		err  error
	}
	results := make([]fileResult, len(files))

	g := new(errgroup.Group)
	g.SetLimit(workers)

	for i, file := range files {
		i, file := i, file
		g.Go(func() error {
			defer func() {
				if r := recover(); r != nil {
					results[i] = fileResult{path: file, err: fmt.Errorf("panic: %v", r)}
				}
			}()
			results[i] = fileResult{path: file, err: DecryptFileAuto(file, password)}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	result := &DirResult{Skipped: skipped}
	for _, r := range results {
		if r.err != nil {
			result.Failed = append(result.Failed, r.path)
		} else {
			result.Success = append(result.Success, r.path)
		}
	}

	return result, nil
}
