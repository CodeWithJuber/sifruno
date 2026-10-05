//go:build windows

package operator

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func privateHandle(f *os.File, st os.FileInfo) error {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) != nil || !st.Mode().IsRegular() || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		return errors.New("invalid private file")
	}
	return nil
}
