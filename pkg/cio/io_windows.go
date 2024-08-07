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

package cio

import (
	"context"
	"fmt"
	"io"
	"net/url"

	winio "github.com/Microsoft/go-winio"
	"github.com/containerd/log"
)

const pipeRoot = `\\.\pipe`

// NewFIFOSetInDir returns a new set of fifos for the task
func NewFIFOSetInDir(_, id string, terminal bool) (*FIFOSet, error) {
	stderrPipe := ""
	if !terminal {
		stderrPipe = fmt.Sprintf(`%s\ctr-%s-stderr`, pipeRoot, id)
	}
	return NewFIFOSet(Config{
		Terminal: terminal,
		Stdin:    fmt.Sprintf(`%s\ctr-%s-stdin`, pipeRoot, id),
		Stdout:   fmt.Sprintf(`%s\ctr-%s-stdout`, pipeRoot, id),
		Stderr:   stderrPipe,
	}, nil), nil
}

func copyIO(fifos *FIFOSet, ioset *Streams) (_ *cio, retErr error) {
	cios := &cio{config: fifos.Config}

	defer func() {
		if retErr != nil {
			_ = cios.Close()
		}
	}()

	if fifos.Stdin != "" {
		l, err := winio.ListenPipe(fifos.Stdin, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create stdin pipe %s: %w", fifos.Stdin, err)
		}
		cios.closers = append(cios.closers, l)

		go func() {
			c, err := l.Accept()
			if err != nil {
				log.L.WithError(err).Errorf("failed to accept stdin connection on %s", fifos.Stdin)
				return
			}

			p := bufPool.Get().(*[]byte)
			defer bufPool.Put(p)

			io.CopyBuffer(c, ioset.Stdin, *p)
			c.Close()
			l.Close()
		}()
	}

	if fifos.Stdout != "" {
		l, err := winio.ListenPipe(fifos.Stdout, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout pipe %s: %w", fifos.Stdout, err)
		}
		cios.closers = append(cios.closers, l)

		go func() {
			c, err := l.Accept()
			if err != nil {
				log.L.WithError(err).Errorf("failed to accept stdout connection on %s", fifos.Stdout)
				return
			}

			p := bufPool.Get().(*[]byte)
			defer bufPool.Put(p)

			io.CopyBuffer(ioset.Stdout, c, *p)
			c.Close()
			l.Close()
		}()
	}

	if fifos.Stderr != "" {
		l, err := winio.ListenPipe(fifos.Stderr, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create stderr pipe %s: %w", fifos.Stderr, err)
		}
		cios.closers = append(cios.closers, l)

		go func() {
			c, err := l.Accept()
			if err != nil {
				log.L.WithError(err).Errorf("failed to accept stderr connection on %s", fifos.Stderr)
				return
			}

			p := bufPool.Get().(*[]byte)
			defer bufPool.Put(p)

			io.CopyBuffer(ioset.Stderr, c, *p)
			c.Close()
			l.Close()
		}()
	}

	return cios, nil
}

// NewDirectIO returns an IO implementation that exposes the IO streams as io.ReadCloser
// and io.WriteCloser.
func NewDirectIO(stdin io.WriteCloser, stdout, stderr io.ReadCloser, terminal bool) *DirectIO {
	return &DirectIO{
		pipes: pipes{
			Stdin:  stdin,
			Stdout: stdout,
			Stderr: stderr,
		},
		cio: cio{
			config: Config{Terminal: terminal},
		},
	}
}

// NewDirectIOFromFIFOSet returns an IO implementation that exposes the IO streams as io.ReadCloser
// and io.WriteCloser.
func NewDirectIOFromFIFOSet(ctx context.Context, stdin io.WriteCloser, stdout, stderr io.ReadCloser, fifos *FIFOSet) *DirectIO {
	_, cancel := context.WithCancel(ctx)
	pipes := pipes{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}
	return &DirectIO{
		pipes: pipes,
		cio: cio{
			config:  fifos.Config,
			closers: append(pipes.closers(), fifos),
			cancel:  cancel,
		},
	}
}

// TerminalLogURI provides the raw logging URI
// as well as sets the terminal option to true.
func TerminalLogURI(uri *url.URL) Creator {
	return func(_ string) (IO, error) {
		return &logURI{
			config: Config{
				Terminal: true,
				Stdout:   uri.String(),

				// Windows HCSShim requires that stderr is an empty string when using terminal.
				// https://github.com/microsoft/hcsshim/blob/200feabd854da69f615a598ed6a1263ce9531676/cmd/containerd-shim-runhcs-v1/service_internal.go#L127
				Stderr: "",
			},
		}, nil
	}
}

// TerminalBinaryIO forwards container STDOUT|STDERR directly to a logging binary
// It also sets the terminal option to true
func TerminalBinaryIO(binary string, args map[string]string) Creator {
	return func(_ string) (IO, error) {
		uri, err := LogURIGenerator("binary", binary, args)
		if err != nil {
			return nil, err
		}

		return &logURI{
			config: Config{
				Terminal: true,
				Stdout:   uri.String(),

				// Windows HCSShim requires that stderr is an empty string when using terminal.
				// https://github.com/microsoft/hcsshim/blob/200feabd854da69f615a598ed6a1263ce9531676/cmd/containerd-shim-runhcs-v1/service_internal.go#L127
				Stderr: "",
			},
		}, nil
	}
}
