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

package sys

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// TestGetLocalListenerNamedPipe verifies that every spelling of a pipe
// address listens on the same pipe.
func TestGetLocalListenerNamedPipe(t *testing.T) {
	name := "containerd-test-" + strings.ReplaceAll(t.Name(), "/", "-")
	for _, address := range []string{
		`\\.\pipe\` + name,
		"//./pipe/" + name,
		"npipe:////./pipe/" + name,
		"npipe://./pipe/" + name,
	} {
		t.Run(address, func(t *testing.T) {
			l, err := GetLocalListener(address, 0, 0)
			if err != nil {
				t.Fatalf("GetLocalListener(%q) failed: %v", address, err)
			}
			defer l.Close()

			checkAccept(t, l, func() (net.Conn, error) { return winio.DialPipe("//./pipe/"+name, nil) })
		})
	}
}

// pathOfLen returns a path of exactly n bytes in dir.
func pathOfLen(t *testing.T, dir string, n int) string {
	t.Helper()
	name := n - len(dir) - 1
	if name < 1 {
		t.Skipf("%q leaves no room for a file name in %d bytes", dir, n)
	}
	return filepath.Join(dir, strings.Repeat("a", name))
}

// TestCreateUnixSocketPathLength verifies that a path over the sun_path limit
// is rejected here rather than passed to the OS.
func TestCreateUnixSocketPathLength(t *testing.T) {
	dir := shortTempDir(t)

	l, err := createUnixSocket(pathOfLen(t, dir, maxUnixPathLen))
	if err != nil {
		t.Fatalf("a path of %d bytes should be accepted: %v", maxUnixPathLen, err)
	}
	l.Close()

	for _, n := range []int{maxUnixPathLen + 1, 2 * maxUnixPathLen} {
		path := pathOfLen(t, dir, n)
		l, err := createUnixSocket(path)
		if err == nil {
			l.Close()
			t.Fatalf("a path of %d bytes should be rejected", n)
		}
		if !strings.Contains(err.Error(), "too long") {
			t.Errorf("path of %d bytes: got %v, want a \"too long\" error", n, err)
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("a rejected path must not be created: %v", err)
		}
	}
}

// TestCreateUnixSocketOverDirectory verifies that a directory at the socket
// path is rejected and left alone, as os.Remove would delete an empty one.
func TestCreateUnixSocketOverDirectory(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "test.sock")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	l, err := createUnixSocket(path)
	if err == nil {
		l.Close()
		t.Fatal("expected an error for a socket path that is a directory")
	}
	if fi, err := os.Lstat(path); err != nil || !fi.IsDir() {
		t.Errorf("the directory at %q must be left in place: %v", path, err)
	}
}

// TestCreateUnixSocketDACL verifies that only Builtin Administrators, Local
// System and the user running containerd can reach the socket, which is
// root-equivalent.
func TestCreateUnixSocketDACL(t *testing.T) {
	sockPath := filepath.Join(shortTempDir(t), "test.sock")

	l, err := createUnixSocket(sockPath)
	if err != nil {
		t.Fatalf("createUnixSocket(%q) failed: %v", sockPath, err)
	}
	defer l.Close()

	checkDACL(t, sockPath, expectedTrustees(t))
}

// TestCreateUnixSocketParentDACL verifies that a parent directory created for
// the socket admits the user running containerd, which could otherwise not
// traverse it to reach the socket when running non-elevated.
func TestCreateUnixSocketParentDACL(t *testing.T) {
	dir := filepath.Join(shortTempDir(t), "state")

	l, err := createUnixSocket(filepath.Join(dir, "test.sock"))
	if err != nil {
		t.Fatalf("createUnixSocket failed: %v", err)
	}
	defer l.Close()

	checkDACL(t, dir, expectedTrustees(t))
}

// expectedTrustees returns the SIDs the socket and its created parent must
// grant: Builtin Administrators, Local System and, unless that is who runs the
// test, the process user.
func expectedTrustees(t *testing.T) []*windows.SID {
	t.Helper()

	var trustees []*windows.SID
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{windows.WinBuiltinAdministratorsSid, windows.WinLocalSystemSid} {
		sid, err := windows.CreateWellKnownSid(wk)
		if err != nil {
			t.Fatalf("CreateWellKnownSid(%d) failed: %v", wk, err)
		}
		trustees = append(trustees, sid)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser failed: %v", err)
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		trustees = append(trustees, user.User.Sid)
	}
	return trustees
}

// checkDACL verifies that path has a non-NULL DACL holding exactly one
// access-allowed ACE per trustee, protected from inheritance so the parent
// cannot widen access.
func checkDACL(t *testing.T, path string, trustees []*windows.SID) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%q) failed: %v", path, err)
	}

	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control failed: %v", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("DACL of %q is not protected: control = %#x, sd = %q", path, control, sd)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL failed: %v", err)
	}
	if dacl == nil {
		t.Fatalf("%q has a NULL DACL, which grants everyone full access", path)
	}
	if int(dacl.AceCount) != len(trustees) {
		t.Errorf("DACL of %q has %d ACEs, want %d: %q", path, dacl.AceCount, len(trustees), sd)
	}
	var granted []*windows.SID
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatalf("GetAce(%d) failed: %v", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Errorf("ACE %d of %q has type %d, want access-allowed: %q", i, path, ace.Header.AceType, sd)
			continue
		}
		granted = append(granted, (*windows.SID)(unsafe.Pointer(&ace.SidStart)))
	}
	for _, trustee := range trustees {
		if !slices.ContainsFunc(granted, trustee.Equals) {
			t.Errorf("DACL %q of %q is missing an ACE for %s", sd, path, trustee)
		}
	}
}
