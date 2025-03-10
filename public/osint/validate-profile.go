package osint

import (
	"fmt"
	"net/http"
	"time"
)

// ValidationResult stores the validation status and details
type ValidationResult struct {
	IsValid     bool
	Confidence  float64
	Markers     []string
	StatusCode  int
	ErrorReason string
}

// ValidateProfile performs advanced validation based on HTTP status code and content
func ValidateProfile(client *http.Client, platform SocialPlatform, url string) ValidationResult {
	result := ValidationResult{
		IsValid:    false,
		Confidence: 0.0,
		Markers:    make([]string, 0),
	}

	// Create request with custom headers to avoid blocks
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("Error creating request: %v", err)
		return result
	}

	// Set realistic headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Perform request with timeout
	client.Timeout = 15 * time.Second
	resp, err := client.Do(req)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("Error performing request: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check common error status codes
	switch resp.StatusCode {
	case http.StatusNotFound:
		result.ErrorReason = "Profile does not exist (404)"
		return result
	case http.StatusForbidden:
		result.ErrorReason = "Access forbidden (403) - possible rate limiting"
		result.Confidence = 0.3 // Profile might exist but access is blocked
		return result
	case http.StatusTooManyRequests:
		result.ErrorReason = "Rate limited (429)"
		result.Confidence = 0.3
		return result
	}

	if resp.StatusCode == http.StatusOK {
		result.IsValid = true
		result.Confidence = 0.7 // Base confidence
		result.Markers = append(result.Markers, "Profile page accessible")

		// Add platform-specific validation
		switch platform.Name {
		case "Twitter":
			if resp.StatusCode == http.StatusOK && resp.Request.URL.String() != url {
				// Twitter redirects non-existent profiles to home
				result.IsValid = false
				result.Confidence = 0.9
				result.ErrorReason = "Profile redirected to home page"
				return result
			}
		case "Instagram":
			if resp.StatusCode == http.StatusOK && resp.Request.URL.String() != url {
				// Instagram redirects non-existent profiles to home
				result.IsValid = false
				result.Confidence = 0.9
				result.ErrorReason = "Profile redirected to login page"
				return result
			}
		case "Facebook":
			if resp.StatusCode == http.StatusOK && resp.Request.URL.Host == "www.facebook.com" && resp.Request.URL.Path == "/" {
				// Facebook redirects non-existent profiles to home
				result.IsValid = false
				result.Confidence = 0.9
				result.ErrorReason = "Profile redirected to home page"
				return result
			}
		}

		result.Confidence = 1.0
	} else {
		result.ErrorReason = fmt.Sprintf("Profile not accessible (Status: %d)", resp.StatusCode)
	}

	return result
}
