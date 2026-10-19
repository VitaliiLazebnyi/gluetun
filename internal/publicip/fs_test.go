package publicip

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_persistPublicIP(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		contents []string
	}{
		"create_file": {
			contents: []string{"1.2.3.4"},
		},
		"overwrite_file": {
			contents: []string{"1.2.3.4", "5.6.7.8"},
		},
		"clear_file": {
			contents: []string{"1.2.3.4", ""},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			path := filepath.Join(directory, "ip")

			for _, content := range testCase.contents {
				err := persistPublicIP(path, content, os.Getuid(), os.Getgid())
				require.NoError(t, err)
			}

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			expectedContent := testCase.contents[len(testCase.contents)-1]
			assert.Equal(t, expectedContent, string(data))

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0o664), info.Mode().Perm())

			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			assert.Len(t, entries, 1, "temporary file left behind")
		})
	}
}
