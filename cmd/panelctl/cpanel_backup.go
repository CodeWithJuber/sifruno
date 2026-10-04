package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"sifruno/internal/cpmove"
)

const (
	maxCPMoveArchiveBytes = int64(32 << 30)
	maxCPMoveCatalogBytes = int64(256 << 20)
	cpMoveInspectTimeout  = 10 * time.Minute
)

var errCPMoveUsage = errors.New("usage: panelctl backup inspect --from FILE --out NEW.jsonl")

// runBackup deliberately uses only local file operations. It does not initialize
// panel authentication, application state, provider clients, or network access.
func runBackup(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] != "inspect" {
		return errCPMoveUsage
	}
	flags := flag.NewFlagSet("backup inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	from := flags.String("from", "", "Original TAR or TAR.GZ archive")
	outPath := flags.String("out", "", "New catalog JSONL output")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *from == "" || *outPath == "" {
		return errCPMoveUsage
	}

	inRoot, inName, err := transferRoot(*from)
	if err != nil {
		return errors.New("backup input path is unavailable or unsafe")
	}
	defer inRoot.Close()
	initial, err := inRoot.Lstat(inName)
	if err != nil || !initial.Mode().IsRegular() || initial.Size() <= 0 || initial.Size() > maxCPMoveArchiveBytes {
		return errors.New("backup input must be a nonempty single-link regular file within 32 GiB")
	}
	in, err := inRoot.Open(inName)
	if err != nil {
		return errors.New("backup input is unavailable")
	}
	defer in.Close()
	before, err := in.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(initial, before) || before.Size() != initial.Size() || !before.ModTime().Equal(initial.ModTime()) || guardTransferHandle(in, before) != nil {
		return errors.New("backup input must be an unchanged single-link regular file")
	}

	outRoot, outName, err := transferRoot(*outPath)
	if err != nil {
		return errors.New("catalog output path is unavailable or unsafe")
	}
	defer outRoot.Close()
	output, err := outRoot.OpenFile(outName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("catalog output must be a new file; existing paths are refused")
	}
	var outputInfo os.FileInfo
	identityKnown := false
	outputClosed := false
	complete := false
	defer func() {
		candidate := outputInfo
		if !identityKnown && !outputClosed {
			candidate, _ = output.Stat()
		}
		if !outputClosed {
			_ = output.Close()
			outputClosed = true
		}
		if !complete && candidate != nil {
			if current, statErr := outRoot.Lstat(outName); statErr == nil && current.Mode().IsRegular() && os.SameFile(candidate, current) {
				_ = outRoot.Remove(outName)
			}
		}
	}()
	outputInfo, err = output.Stat()
	if err != nil {
		return errors.New("catalog output identity is unavailable")
	}
	identityKnown = true
	if !outputInfo.Mode().IsRegular() || guardTransferHandle(output, outputInfo) != nil {
		return errors.New("catalog output must be a single-link regular file")
	}

	ctx, cancel := context.WithTimeout(context.Background(), cpMoveInspectTimeout)
	defer cancel()
	limited := &boundedCatalogWriter{w: output, remaining: maxCPMoveCatalogBytes}
	limits := cpmove.DefaultLimits()
	if limits.MaxArchiveBytes > maxCPMoveArchiveBytes {
		limits.MaxArchiveBytes = maxCPMoveArchiveBytes
	}
	summary, err := cpmove.WriteCatalog(ctx, io.LimitReader(in, maxCPMoveArchiveBytes+1), limited, limits)
	if err != nil || !summary.Complete || summary.ArchiveBytes > maxCPMoveArchiveBytes || limited.exceeded {
		return errors.New("backup could not be completely cataloged within the bounded limits")
	}
	after, err := in.Stat()
	inputPath, pathErr := inRoot.Lstat(inName)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, inputPath) || !inputPath.Mode().IsRegular() || !after.Mode().IsRegular() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || guardTransferHandle(in, after) != nil {
		return errors.New("backup input changed during cataloging")
	}
	if err = output.Sync(); err != nil {
		return errors.New("catalog output could not be persisted")
	}
	outputAfter, err := output.Stat()
	outputPath, pathErr := outRoot.Lstat(outName)
	if err != nil || pathErr != nil || !outputAfter.Mode().IsRegular() || !os.SameFile(outputInfo, outputAfter) || !os.SameFile(outputInfo, outputPath) || guardTransferHandle(output, outputAfter) != nil {
		return errors.New("catalog output identity changed")
	}
	if err = output.Close(); err != nil {
		outputClosed = true
		return errors.New("catalog output could not be closed")
	}
	outputClosed = true
	outputPath, pathErr = outRoot.Lstat(outName)
	if pathErr != nil || !outputPath.Mode().IsRegular() || !os.SameFile(outputInfo, outputPath) {
		return errors.New("catalog output identity changed")
	}
	if err = json.NewEncoder(out).Encode(summary); err != nil {
		return errors.New("catalog summary could not be written")
	}
	complete = true
	return nil
}

type boundedCatalogWriter struct {
	w         io.Writer
	remaining int64
	exceeded  bool
}

func (w *boundedCatalogWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		w.exceeded = true
		return 0, errors.New("catalog limit exceeded")
	}
	if int64(len(p)) > w.remaining {
		written, err := w.w.Write(p[:w.remaining])
		w.remaining -= int64(written)
		w.exceeded = true
		if err != nil {
			return written, err
		}
		return written, errors.New("catalog limit exceeded")
	}
	written, err := w.w.Write(p)
	w.remaining -= int64(written)
	return written, err
}
