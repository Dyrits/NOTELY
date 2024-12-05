package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(context *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		expected  string
		expectErr error
	}{
		{
			name:      "Valid API Key",
			headers:   http.Header{"Authorization": []string{"ApiKey valid_key"}},
			expected:  "valid_key",
			expectErr: nil,
		},
		{
			name:      "No Authorization Header",
			headers:   http.Header{},
			expected:  "",
			expectErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "Malformed Authorization Header",
			headers:   http.Header{"Authorization": []string{"Bearer token"}},
			expected:  "",
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name:      "Incomplete Authorization Header",
			headers:   http.Header{"Authorization": []string{"ApiKey"}},
			expected:  "",
			expectErr: errors.New("malformed authorization header"),
		},
	}

	for _, scenario := range tests {
		context.Run(scenario.name, func(context *testing.T) {
			got, err := GetAPIKey(scenario.headers)

			if err != nil && err.Error() != scenario.expectErr.Error() {
				context.Errorf("GetAPIKey() error = %v, wantErr %v", err, scenario.expectErr)
				return
			}

			if got != scenario.expected {
				context.Errorf("GetAPIKey() = %v, expected %v", got, scenario.expected)
			}
		})
	}
}
