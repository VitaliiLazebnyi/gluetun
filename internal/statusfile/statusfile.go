// Package statusfile writes status files, such as the public IP
// address file or the forwarded port file, readable by other programs.
package statusfile

import (
	"fmt"
	"io/fs"
	"os"
)

// Write writes the content to the file at the given path in place,
// creating it if needed, sets its permissions to 0664 and chowns it
// to the given puid and pgid. A puid or pgid of -1 leaves the
// corresponding ownership unchanged.
//
// The file is written in place (and not renamed over) so single file
// bind mounts, hardlinks and inotify watches on it keep working. The
// content is written before the chmod and chown, so it is not lost
// if either of these fails.
// The file is only chmoded if its permissions differ from 0664:
// once the file is chowned to puid, chmoding it requires CAP_FOWNER
// which may not be available, for example with cap_drop ALL.
// Writing to the file still requires CAP_DAC_OVERRIDE once it is
// owned by puid.
func Write(path string, content []byte, puid, pgid int) (err error) {
	// TODO v4: remove world permission (0660)
	const permission = fs.FileMode(0o664)
	file, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY|os.O_CREATE, permission)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}
	defer func() {
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = fmt.Errorf("closing file: %w", closeErr)
		}
	}()

	_, err = file.Write(content)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("getting file information: %w", err)
	}

	// chmod explicitly since OpenFile is subject to the umask,
	// and it does not change the permissions of an existing file.
	if info.Mode().Perm() != permission {
		err = file.Chmod(permission)
		if err != nil {
			return fmt.Errorf("setting file permissions: %w", err)
		}
	}

	err = file.Chown(puid, pgid)
	if err != nil {
		return fmt.Errorf("chowning file: %w", err)
	}

	return nil
}
