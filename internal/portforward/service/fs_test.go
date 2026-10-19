package service

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func Test_Service_writePortForwardedFile(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		writes          [][]uint16
		expectedContent string
	}{
		"create_file": {
			writes:          [][]uint16{{1000, 2000}},
			expectedContent: "1000\n2000",
		},
		"overwrite_file": {
			writes:          [][]uint16{{1000}, {3000}},
			expectedContent: "3000",
		},
		"clear_file": {
			writes:          [][]uint16{{1000}, nil},
			expectedContent: "",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)

			directory := t.TempDir()
			path := filepath.Join(directory, "forwarded_port")

			logger := NewMockLogger(ctrl)
			for _, ports := range testCase.writes {
				if len(ports) == 0 {
					logger.EXPECT().Info("clearing port file " + path)
				} else {
					logger.EXPECT().Info("writing port file " + path)
				}
			}

			service := &Service{
				settings: Settings{Filepath: path},
				puid:     os.Getuid(),
				pgid:     os.Getgid(),
				logger:   logger,
			}

			for _, ports := range testCase.writes {
				err := service.writePortForwardedFile(ports)
				require.NoError(t, err)
			}

			data, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedContent, string(data))

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0o664), info.Mode().Perm())

			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			assert.Len(t, entries, 1, "temporary file left behind")
		})
	}
}
