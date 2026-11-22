//go:build !unix

package htaccess

import "os"

const openFlags = os.O_RDONLY
