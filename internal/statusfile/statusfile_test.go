package statusfile

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Write(t *testing.T) {
	t.Parallel()

	const root = 0
	isRoot := os.Geteuid() == root

	testCases := map[string]struct {
		missingParent   bool
		existingContent string
		existingMode    fs.FileMode // 0 means no existing file
		content         string
		chownToRoot     bool
		// errMessage is the expected error message substring,
		// which can differ depending on whether the test runs as root.
		errMessage      string
		expectedContent string
		expectedMode    fs.FileMode
	}{
		"create_new_file": {
			content:         "1.2.3.4",
			expectedContent: "1.2.3.4",
			expectedMode:    0o664,
		},
		"overwrite_existing_file": {
			existingContent: "1.2.3.4",
			existingMode:    0o664,
			content:         "5.6",
			expectedContent: "5.6",
			expectedMode:    0o664,
		},
		"clear_existing_file": {
			existingContent: "1.2.3.4",
			existingMode:    0o664,
			expectedContent: "",
			expectedMode:    0o664,
		},
		"existing_file_with_mode_0600": {
			existingContent: "1.2.3.4",
			existingMode:    0o600,
			content:         "5.6.7.8",
			expectedContent: "5.6.7.8",
			expectedMode:    0o664,
		},
		"existing_file_with_mode_0644": {
			existingContent: "1.2.3.4",
			existingMode:    0o644,
			content:         "5.6.7.8",
			expectedContent: "5.6.7.8",
			expectedMode:    0o664,
		},
		"existing_read_only_file": {
			existingContent: "1.2.3.4",
			existingMode:    0o444,
			content:         "5.6.7.8",
			errMessage: map[bool]string{
				true:  "",
				false: "opening file: open ",
			}[isRoot],
			expectedContent: map[bool]string{
				true:  "5.6.7.8",
				false: "1.2.3.4",
			}[isRoot],
			expectedMode: map[bool]fs.FileMode{
				true:  0o664,
				false: 0o444,
			}[isRoot],
		},
		"chown_failure_keeps_content": {
			content:     "1.2.3.4",
			chownToRoot: true,
			errMessage: map[bool]string{
				true:  "",
				false: "chowning file: chown ",
			}[isRoot],
			expectedContent: "1.2.3.4",
			expectedMode:    0o664,
		},
		"missing_parent_directory": {
			missingParent: true,
			content:       "1.2.3.4",
			errMessage:    "opening file: open ",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "file")
			if testCase.missingParent {
				path = filepath.Join(t.TempDir(), "missing", "file")
			}

			if testCase.existingMode != 0 {
				err := os.WriteFile(path, []byte(testCase.existingContent), testCase.existingMode)
				require.NoError(t, err)
				// chmod explicitly since WriteFile is subject to the umask
				err = os.Chmod(path, testCase.existingMode)
				require.NoError(t, err)
			}

			puid, pgid := os.Getuid(), os.Getgid()
			if testCase.chownToRoot {
				puid, pgid = root, root
			}

			err := Write(path, []byte(testCase.content), puid, pgid)

			if testCase.errMessage != "" {
				assert.ErrorContains(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}

			if testCase.missingParent {
				_, err = os.Stat(path)
				assert.ErrorIs(t, err, fs.ErrNotExist)
				return
			}

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedContent, string(data))

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedMode, info.Mode().Perm())
		})
	}
}
