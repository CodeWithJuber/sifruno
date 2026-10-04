//go:build windows

package main

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
)

func guardTransferHandle(file *os.File, info os.FileInfo) error {
	var value windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &value) != nil || value.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.Mode().IsRegular() && value.NumberOfLinks != 1) {
		return errors.New("unsafe archive file")
	}
	return nil
}
func guardTransferPath(path string) error {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return errors.New("archive requires a local disk path")
	}
	drive, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return errors.New("invalid archive disk")
	}
	switch windows.GetDriveType(drive) {
	case windows.DRIVE_FIXED, windows.DRIVE_REMOVABLE, windows.DRIVE_RAMDISK, windows.DRIVE_CDROM:
	default:
		return errors.New("archive requires a local disk")
	}
	if strings.Contains(filepath.Base(path), ":") {
		return errors.New("archive streams refused")
	}
	for {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return errors.New("invalid archive path")
		}
		attrs, err := windows.GetFileAttributes(p)
		if err == nil && attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("archive reparse paths refused")
		}
		if err != nil && !os.IsNotExist(err) {
			return errors.New("archive path unavailable")
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return nil
}
