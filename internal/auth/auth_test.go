package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		shouldError   bool
	}{
		{
			name: "valid API key",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-api-key-123"},
			},
			expectedKey:   "test-api-key-123",
			expectedError: nil,
			shouldError:   false,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			shouldError:   true,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
			shouldError:   true,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer test-token"},
			},
			expectedKey: "",
			shouldError: true,
		},
		{
			name: "malformed header - only ApiKey without key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			shouldError: true,
		},
		{
			name: "malformed header - wrong case",
			headers: http.Header{
				"Authorization": []string{"apikey test-key"},
			},
			expectedKey: "",
			shouldError: true,
		},
		{
			name: "valid API key with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey  test-key-with-spaces"},
			},
			expectedKey:   "",
			expectedError: nil,
			shouldError:   false,
		},
		{
			name: "valid API key with multiple parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-key extra-part"},
			},
			expectedKey:   "test-key",
			expectedError: nil,
			shouldError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				if tt.expectedError != nil && err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}
}

func TestErrNoAuthHeaderIncluded(t *testing.T) {
	// Test that the error variable is properly defined
	if ErrNoAuthHeaderIncluded == nil {
		t.Error("ErrNoAuthHeaderIncluded should not be nil")
	}

	expectedMessage := "no authorization header included"
	if ErrNoAuthHeaderIncluded.Error() != expectedMessage {
		t.Errorf("expected error message %q, got %q", expectedMessage, ErrNoAuthHeaderIncluded.Error())
	}
}
