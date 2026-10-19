package publicip

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// persistPublicIP writes the content to a temporary file owned by the
// current process user, which is then chmoded, chowned and renamed
// over the destination path. Writing to a new file every time avoids
// requiring CAP_FOWNER to chmod a file already chowned to PUID, and
// CAP_DAC_OVERRIDE to write to it.
func persistPublicIP(path string, content string, puid, pgid int) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	defer func() {
		if err != nil {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}()

	_, err = file.WriteString(content)
	if err != nil {
		return fmt.Errorf("writing temporary file: %w", err)
	}

	// TODO v4: remove world permission (0660)
	const permission = fs.FileMode(0o664)
	err = file.Chmod(permission)
	if err != nil {
		return fmt.Errorf("setting file permissions: %w", err)
	}

	err = file.Chown(puid, pgid)
	if err != nil {
		return fmt.Errorf("chowning file: %w", err)
	}

	err = file.Close()
	if err != nil {
		return fmt.Errorf("closing temporary file: %w", err)
	}

	err = os.Rename(file.Name(), path)
	if err != nil {
		return fmt.Errorf("renaming temporary file: %w", err)
	}

	return nil
}
