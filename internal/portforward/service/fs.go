package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (s *Service) writePortForwardedFile(ports []uint16) (err error) {
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprint(int(port))
	}
	fileData := []byte(strings.Join(portStrings, "\n"))

	path := s.settings.Filepath
	if len(ports) == 0 {
		s.logger.Info("clearing port file " + path)
	} else {
		s.logger.Info("writing port file " + path)
	}

	// Write to a temporary file owned by the current process user, and
	// then rename it over the destination path. Writing to a new file
	// every time avoids requiring CAP_FOWNER to chmod a file already
	// chowned to PUID, and CAP_DAC_OVERRIDE to write to it.
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

	_, err = file.Write(fileData)
	if err != nil {
		return fmt.Errorf("writing temporary file: %w", err)
	}

	// TODO v4: remove world permission (0660)
	const perms = os.FileMode(0o664)
	err = file.Chmod(perms)
	if err != nil {
		return fmt.Errorf("setting file permissions: %w", err)
	}

	// TODO v4: is it necessary/desirable to chown to PUID?
	// PGID already has read/write access after the chmod.
	err = file.Chown(s.puid, s.pgid)
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
