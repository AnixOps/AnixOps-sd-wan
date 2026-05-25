package system

import (
	"context"
	"os"
)

type RecordedCommand struct {
	Name string
	Args []string
}

type RecordingRunner struct {
	Commands []RecordedCommand
	Err      error
}

func (r *RecordingRunner) Run(ctx context.Context, name string, args ...string) error {
	r.Commands = append(r.Commands, RecordedCommand{Name: name, Args: append([]string(nil), args...)})
	return r.Err
}

type RecordingWriter struct {
	Files map[string][]byte
	Perms map[string]os.FileMode
	Err   error
}

func NewRecordingWriter() *RecordingWriter {
	return &RecordingWriter{
		Files: make(map[string][]byte),
		Perms: make(map[string]os.FileMode),
	}
}

func (w *RecordingWriter) WriteFile(path string, data []byte, perm os.FileMode) error {
	if w.Err != nil {
		return w.Err
	}
	w.Files[path] = append([]byte(nil), data...)
	w.Perms[path] = perm
	return nil
}
