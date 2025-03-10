/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package fs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/log"
	"golang.org/x/sync/errgroup"
)

// ChangeKind is the type of modification that
// a change is making.
type ChangeKind int

const (
	// ChangeKindUnmodified represents an unmodified
	// file
	ChangeKindUnmodified = iota

	// ChangeKindAdd represents an addition of
	// a file
	ChangeKindAdd

	// ChangeKindModify represents a change to
	// an existing file
	ChangeKindModify

	// ChangeKindDelete represents a delete of
	// a file
	ChangeKindDelete
)

func (k ChangeKind) String() string {
	switch k {
	case ChangeKindUnmodified:
		return "unmodified"
	case ChangeKindAdd:
		return "add"
	case ChangeKindModify:
		return "modify"
	case ChangeKindDelete:
		return "delete"
	default:
		return ""
	}
}

// Change represents single change between a diff and its parent.
type Change struct {
	Kind ChangeKind
	Path string
}

// ChangeFunc is the type of function called for each change
// computed during a directory changes calculation.
type ChangeFunc func(ChangeKind, string, os.FileInfo, error) error

// Changes computes changes between two directories calling the
// given change function for each computed change. The first
// directory is intended to the base directory and second
// directory the changed directory.
//
// The change callback is called by the order of path names and
// should be appliable in that order.
//
//	Due to this apply ordering, the following is true
//	- Removed directory trees only create a single change for the root
//	  directory removed. Remaining changes are implied.
//	- A directory which is modified to become a file will not have
//	  delete entries for sub-path items, their removal is implied
//	  by the removal of the parent directory.
//
// Opaque directories will not be treated specially and each file
// removed from the base directory will show up as a removal.
//
// File content comparisons will be done on files which have timestamps
// which may have been truncated. If either of the files being compared
// has a zero value nanosecond value, each byte will be compared for
// differences. If 2 files have the same seconds value but different
// nanosecond values where one of those values is zero, the files will
// be considered unchanged if the content is the same. This behavior
// is to account for timestamp truncation during archiving.
func Changes(ctx context.Context, a, b string, changeFn ChangeFunc) error {
	if a == "" {
		log.G(ctx).Debugf("Using single walk diff for %s", b)
		return addDirChanges(ctx, changeFn, b)
	}

	log.G(ctx).Debugf("Using double walk diff for %s from %s", b, a)
	return doubleWalkDiff(ctx, changeFn, a, b)
}

func addDirChanges(ctx context.Context, changeFn ChangeFunc, root string) error {
	return filepath.Walk(root, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Rebase path
		path, err = filepath.Rel(root, path)
		if err != nil {
			return err
		}

		path = filepath.Join(string(os.PathSeparator), path)

		// Skip root
		if path == string(os.PathSeparator) {
			return nil
		}

		return changeFn(ChangeKindAdd, path, f, nil)
	})
}

// DiffChangeSource is the source of diff directory.
type DiffSource int

const (
	// DiffSourceOverlayFS indicates that a diff directory is from
	// OverlayFS.
	DiffSourceOverlayFS DiffSource = iota
)

// diffDirOptions is used when the diff can be directly calculated from
// a diff directory to its base, without walking both trees.
type diffDirOptions struct {
	skipChange   func(string, os.FileInfo) (bool, error)
	deleteChange func(string, string, os.FileInfo, ChangeFunc) (bool, error)
}

// DiffDirChanges walks the diff directory and compares changes against the base.
//
// NOTE: If all the children of a dir are removed, or that dir are recreated
// after remove, we will mark non-existing `.wh..opq` file as deleted. It's
// unlikely to create explicit whiteout files for all the children and all
// descendants. And based on OCI spec, it's not possible to create a file or
// dir with a name beginning with `.wh.`. So, after `.wh..opq` file has been
// deleted, the ChangeFunc, the receiver will add whiteout prefix to create a
// opaque whiteout `.wh..wh..opq`.
//
// REF: https://github.com/opencontainers/image-spec/blob/v1.0/layer.md#whiteouts
func DiffDirChanges(ctx context.Context, baseDir, diffDir string, source DiffSource, changeFn ChangeFunc) error {
	var o *diffDirOptions

	switch source {
	case DiffSourceOverlayFS:
		o = &diffDirOptions{
			deleteChange: overlayFSWhiteoutConvert,
		}
	default:
		return errors.New("unknown diff change source")
	}

	changedDirs := make(map[string]struct{})
	return filepath.Walk(diffDir, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Rebase path
		path, err = filepath.Rel(diffDir, path)
		if err != nil {
			return err
		}

		path = filepath.Join(string(os.PathSeparator), path)

		// Skip root
		if path == string(os.PathSeparator) {
			return nil
		}

		if o.skipChange != nil {
			if skip, err := o.skipChange(path, f); skip {
				return err
			}
		}

		var kind ChangeKind

		deletedFile := false

		if o.deleteChange != nil {
			deletedFile, err = o.deleteChange(diffDir, path, f, changeFn)
			if err != nil {
				return err
			}

			_, err = os.Stat(filepath.Join(baseDir, path))
			if err != nil {
				if !os.IsNotExist(err) {
					return err
				}
				deletedFile = false
			}
		}

		// Find out what kind of modification happened
		if deletedFile {
			kind = ChangeKindDelete
		} else {
			// Otherwise, the file was added
			kind = ChangeKindAdd

			// ...Unless it already existed in a baseDir, in which case, it's a modification
			stat, err := os.Stat(filepath.Join(baseDir, path))
			if err != nil && !os.IsNotExist(err) {
				return err
			}
			if err == nil {
				// The file existed in the baseDir, so that's a modification

				// However, if it's a directory, maybe it wasn't actually modified.
				// If you modify /foo/bar/baz, then /foo will be part of the changed files only because it's the parent of bar
				if stat.IsDir() && f.IsDir() {
					if f.Size() == stat.Size() && f.Mode() == stat.Mode() && sameFsTime(f.ModTime(), stat.ModTime()) {
						// Both directories are the same, don't record the change
						return nil
					}
				}
				kind = ChangeKindModify
			}
		}

		// If /foo/bar/file.txt is modified, then /foo/bar must be part of the changed files.
		// This block is here to ensure the change is recorded even if the
		// modify time, mode and size of the parent directory in the rw and ro layers are all equal.
		// Check https://github.com/docker/docker/pull/13590 for details.
		if f.IsDir() {
			changedDirs[path] = struct{}{}
		}

		if kind == ChangeKindAdd || kind == ChangeKindDelete {
			parent := filepath.Dir(path)

			if _, ok := changedDirs[parent]; !ok && parent != "/" {
				pi, err := os.Stat(filepath.Join(diffDir, parent))
				if err := changeFn(ChangeKindModify, parent, pi, err); err != nil {
					return err
				}
				changedDirs[parent] = struct{}{}
			}
		}

		if kind == ChangeKindDelete {
			f = nil
		}
		return changeFn(kind, path, f, nil)
	})
}

// doubleWalkDiff walks both directories to create a diff
func doubleWalkDiff(ctx context.Context, changeFn ChangeFunc, a, b string) (err error) {
	g, ctx := errgroup.WithContext(ctx)

	var (
		c1 = make(chan *currentPath)
		c2 = make(chan *currentPath)

		f1, f2 *currentPath
		rmdir  string
	)
	g.Go(func() error {
		defer close(c1)
		return pathWalk(ctx, a, c1)
	})
	g.Go(func() error {
		defer close(c2)
		return pathWalk(ctx, b, c2)
	})
	g.Go(func() error {
		for c1 != nil || c2 != nil {
			if f1 == nil && c1 != nil {
				f1, err = nextPath(ctx, c1)
				if err != nil {
					return err
				}
				if f1 == nil {
					c1 = nil
				}
			}

			if f2 == nil && c2 != nil {
				f2, err = nextPath(ctx, c2)
				if err != nil {
					return err
				}
				if f2 == nil {
					c2 = nil
				}
			}
			if f1 == nil && f2 == nil {
				continue
			}

			var f os.FileInfo
			k, p := pathChange(f1, f2)
			switch k {
			case ChangeKindAdd:
				if rmdir != "" {
					rmdir = ""
				}
				f = f2.f
				f2 = nil
			case ChangeKindDelete:
				// Check if this file is already removed by being
				// under of a removed directory
				if rmdir != "" && strings.HasPrefix(f1.path, rmdir) {
					f1 = nil
					continue
				} else if f1.f.IsDir() {
					rmdir = f1.path + string(os.PathSeparator)
				} else if rmdir != "" {
					rmdir = ""
				}
				f1 = nil
			case ChangeKindModify:
				same, err := sameFile(f1, f2)
				if err != nil {
					return err
				}
				if f1.f.IsDir() && !f2.f.IsDir() {
					rmdir = f1.path + string(os.PathSeparator)
				} else if rmdir != "" {
					rmdir = ""
				}
				f = f2.f
				f1 = nil
				f2 = nil
				if same {
					if !isLinked(f) {
						continue
					}
					k = ChangeKindUnmodified
				}
			}
			if err := changeFn(k, p, f, nil); err != nil {
				return err
			}
		}
		return nil
	})

	return g.Wait()
}
