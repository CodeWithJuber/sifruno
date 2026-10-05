//go:build windows

package hostwebgeneration

import (
	"golang.org/x/sys/windows"
	"os"
)

// Windows supports isolated protocol tests under securestate's protected ACL;
// this is not root-broker admission or native Linux execution evidence.
func guardOwner() error { return nil }
func guardDirectory(path string) error {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() {
		return ErrUnavailable
	}
	return nil
}
func guardFile(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrUnavailable
	}
	h, e := windows.CreateFile(windows.StringToUTF16Ptr(path), windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return ErrUnavailable
	}
	defer windows.CloseHandle(h)
	var data windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &data) != nil || data.NumberOfLinks != 1 || data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUnavailable
	}
	return nil
}
