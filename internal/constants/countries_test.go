package constants

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CountryNameToCode(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		name string
		code string
		ok   bool
	}{
		"unknown":            {name: "Atlantis"},
		"case_insensitive":   {name: "united states", code: "us", ok: true},
		"united_kingdom_iso": {name: "United Kingdom", code: "gb", ok: true},
		"city_entry_ignored": {name: "Kuala Lumpur"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			code, ok := CountryNameToCode(testCase.name)

			assert.Equal(t, testCase.code, code)
			assert.Equal(t, testCase.ok, ok)
		})
	}
}
