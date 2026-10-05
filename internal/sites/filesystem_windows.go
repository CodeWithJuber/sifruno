//go:build windows

package sites

import (
	"golang.org/x/sys/windows"
	"os"
)

func guardHandle(file *os.File, info os.FileInfo) error {
	var value windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &value); err != nil {
		return ErrUnavailable
	}
	if value.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.Mode().IsRegular() && value.NumberOfLinks != 1) {
		return ErrUnavailable
	}
	return nil
}

// Go's Windows directory handles do not support fsync. Regular files and bbolt
// transactions are synced; directory durability remains filesystem dependent.
func syncRoot(_ *os.Root, _ string) error { return nil }
