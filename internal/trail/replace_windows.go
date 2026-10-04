//go:build windows

package trail

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FileRenameInformationEx is also used by Go's rooted Windows rename. Unlike
// Go's flags, IGNORE_READONLY_ATTRIBUTE can replace a readonly target without
// first changing its attributes, which would introduce an unjournaled crash
// state. Both names stay relative to an already confined parent handle.
func replaceRootedFile(r *os.Root, source, destination string) error {
	err := r.Rename(source, destination)
	if err == nil || !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return err
	}
	if filepath.Dir(source) != filepath.Dir(destination) {
		return errors.New("restore replacement must stay in one directory")
	}
	parent, err := r.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer parent.Close()
	name, err := windows.NewNTUnicodeString(filepath.Base(source))
	if err != nil {
		return err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(parent.Fd()), ObjectName: name}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var sourceHandle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&sourceHandle, windows.SYNCHRONIZE|windows.DELETE, &oa, &status, nil, 0,
		windows.FILE_SHARE_DELETE|windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(sourceHandle)
	wide, err := windows.UTF16FromString(filepath.Base(destination))
	if err != nil {
		return err
	}
	type renameInformation struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	var header renameInformation
	nameBytes := (len(wide) - 1) * 2
	buffer := make([]byte, int(unsafe.Offsetof(header.FileName))+nameBytes)
	info := (*renameInformation)(unsafe.Pointer(&buffer[0]))
	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS | windows.FILE_RENAME_IGNORE_READONLY_ATTRIBUTE
	info.RootDirectory = windows.Handle(parent.Fd())
	info.FileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&info.FileName[0], len(wide)-1), wide[:len(wide)-1])
	const fileRenameInformationEx = 65
	return windows.NtSetInformationFile(sourceHandle, &status, &buffer[0], uint32(len(buffer)), fileRenameInformationEx)
}
