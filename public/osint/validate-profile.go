package osint

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ValidationResult stores the validation status and details
type ValidationResult struct {
	IsValid     bool
	Confidence  float64
	Markers     []string
	StatusCode  int
	ErrorReason string
	Username    string
	ProfileType string // "personal", "business", "bot", etc.
}

// ValidateProfile performs advanced validation based on HTTP status code, content analysis, and platform-specific heuristics
func ValidateProfile(client *http.Client, platform SocialPlatform, url string, username string) ValidationResult {
	result := ValidationResult{
		IsValid:    false,
		Confidence: 0.0,
		Markers:    make([]string, 0),
		Username:   username,
	}

	// Create request with custom headers to avoid blocks
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("Error creating request: %v", err)
		return result
	}

	// Set realistic headers to avoid detection
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Sec-Ch-Ua", "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"108\"")
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", "\"Windows\"")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Perform request with timeout
	client.Timeout = 15 * time.Second

	// Enable cookie jar and follow redirects, but track them
	var finalURL string
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		finalURL = req.URL.String()
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("Error performing request: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check for redirects
	if finalURL != "" && finalURL != url {
		result.Markers = append(result.Markers, fmt.Sprintf("Redirected to: %s", finalURL))
	}

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

	// Read body content for analysis
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("Error reading response body: %v", err)
		return result
	}
	bodyContent := string(bodyBytes)

	// Generic error phrases that indicate a profile doesn't exist
	nonExistentPhrases := []string{
		"page isn't available",
		"page not found",
		"user not found",
		"doesn't exist",
		"isn't available",
		"account has been suspended",
		"account doesn't exist",
		"this account is private",
		"this profile isn't available",
		"sorry, this page isn't available",
		"the link you followed may be broken",
	}

	for _, phrase := range nonExistentPhrases {
		if strings.Contains(strings.ToLower(bodyContent), strings.ToLower(phrase)) {
			result.IsValid = false
			result.Confidence = 0.9
			result.ErrorReason = fmt.Sprintf("Profile likely doesn't exist: Found '%s'", phrase)
			return result
		}
	}

	if resp.StatusCode == http.StatusOK {
		result.IsValid = true
		result.Confidence = 0.7 // Base confidence
		result.Markers = append(result.Markers, "Profile page accessible")

		// Add platform-specific validation
		switch platform.Name {
		case "Twitter", "X":
			// Check for Twitter-specific indicators
			if strings.Contains(bodyContent, `"This account doesn't exist"`) ||
				strings.Contains(bodyContent, "User not found") {
				result.IsValid = false
				result.Confidence = 0.95
				result.ErrorReason = "Account doesn't exist (content analysis)"
				return result
			}

			// Check for username on the page
			usernamePattern := fmt.Sprintf(`@%s`, regexp.QuoteMeta(username))
			if matched, _ := regexp.MatchString(usernamePattern, bodyContent); matched {
				result.Confidence = 0.95
				result.Markers = append(result.Markers, "Username found in page content")
			}

			// Check for account verification
			if strings.Contains(bodyContent, "verified_user") || strings.Contains(bodyContent, "VerifiedAccount") {
				result.Confidence = 0.99
				result.Markers = append(result.Markers, "Verified account")
			}

		case "Instagram":
			// Check for Instagram-specific indicators
			if strings.Contains(bodyContent, "Sorry, this page") && strings.Contains(bodyContent, "isn't available") {
				result.IsValid = false
				result.Confidence = 0.95
				result.ErrorReason = "Page not available (content analysis)"
				return result
			}

			// Look for user info in JSON data
			profileDataRe := regexp.MustCompile(`"user":{"biography":"(.*?)","id":"(\d+)"`)
			if profileDataRe.MatchString(bodyContent) {
				result.Confidence = 0.95
				result.Markers = append(result.Markers, "User data found in page content")
			}

			// Check for verified badge
			if strings.Contains(bodyContent, "\"is_verified\":true") {
				result.Confidence = 0.99
				result.Markers = append(result.Markers, "Verified account")
			}

		case "Facebook":
			// Check for Facebook-specific indicators
			if strings.Contains(bodyContent, "content not found") ||
				strings.Contains(bodyContent, "page you requested cannot be displayed") {
				result.IsValid = false
				result.Confidence = 0.95
				result.ErrorReason = "Content not found (content analysis)"
				return result
			}

			// Check if URL changed to Facebook's error page format
			if strings.Contains(finalURL, "facebook.com/pages_reaction_units") {
				result.IsValid = false
				result.Confidence = 0.9
				result.ErrorReason = "Redirected to error page"
				return result
			}

			// Try to detect profile type
			if strings.Contains(bodyContent, "\"pageID\"") {
				result.ProfileType = "page"
				result.Markers = append(result.Markers, "Business/Fan page detected")
			} else {
				result.ProfileType = "personal"
				result.Markers = append(result.Markers, "Personal profile detected")
			}

		case "LinkedIn":
			// Check for LinkedIn-specific indicators
			if strings.Contains(bodyContent, "page not found") ||
				strings.Contains(bodyContent, "this page doesn't exist") {
				result.IsValid = false
				result.Confidence = 0.95
				result.ErrorReason = "Page not found (content analysis)"
				return result
			}

			// Check for profile section indicators
			profileSections := 0
			for _, section := range []string{"experience-section", "education-section", "skills-section"} {
				if strings.Contains(bodyContent, section) {
					profileSections++
				}
			}

			if profileSections > 0 {
				result.Confidence += float64(profileSections) * 0.05
				result.Markers = append(result.Markers, fmt.Sprintf("Found %d profile sections", profileSections))
			}

		case "Reddit":
			// Check for Reddit-specific indicators
			if strings.Contains(bodyContent, "Sorry, nobody on Reddit goes by that name") {
				result.IsValid = false
				result.Confidence = 0.95
				result.ErrorReason = "User doesn't exist (content analysis)"
				return result
			}

			// Check for karma indicators - strong sign of real account
			karmaRe := regexp.MustCompile(`(\d+) karma`)
			if karmaRe.MatchString(bodyContent) {
				result.Confidence = 0.9
				result.Markers = append(result.Markers, "Karma count found - active account")
			}

			// Check account age
			if strings.Contains(bodyContent, "redditor for") {
				result.Confidence += 0.05
				result.Markers = append(result.Markers, "Account age indicator found")
			}
		}

		// Check for content that suggests this is a real profile across all platforms
		realUserIndicators := map[string]string{
			"Posts":         "Found user posts",
			"Followers":     "Has followers",
			"Following":     "Is following others",
			"Comments":      "Has comments",
			"Bio":           "Has biography",
			"Profile photo": "Has profile photo",
			"Cover photo":   "Has cover photo",
		}

		indicatorsFound := 0
		for indicator, message := range realUserIndicators {
			indicatorRegex := regexp.MustCompile(fmt.Sprintf(`(?i)%s`, regexp.QuoteMeta(indicator)))
			if indicatorRegex.MatchString(bodyContent) {
				result.Markers = append(result.Markers, message)
				indicatorsFound++
			}
		}

		// Adjust confidence based on indicators found
		if indicatorsFound > 0 {
			// Add up to 0.3 to confidence based on indicators
			result.Confidence += math.Min(float64(indicatorsFound)*0.05, 0.3)
		}

		// Cap confidence at 1.0
		if result.Confidence > 1.0 {
			result.Confidence = 1.0
		}
	} else {
		result.ErrorReason = fmt.Sprintf("Profile not accessible (Status: %d)", resp.StatusCode)
	}

	return result
}

// CheckCaptchaOrLogin determines if the page contains login walls or captcha challenges
func CheckCaptchaOrLogin(content string) (bool, string) {
	captchaIndicators := []string{
		"captcha",
		"robot",
		"human verification",
		"security check",
		"prove you're human",
		"verify your identity",
	}

	loginIndicators := []string{
		"log in",
		"login",
		"sign in",
		"signin",
		"create an account",
		"join now",
	}

	for _, indicator := range captchaIndicators {
		if strings.Contains(strings.ToLower(content), indicator) {
			return true, "captcha"
		}
	}

	for _, indicator := range loginIndicators {
		if strings.Contains(strings.ToLower(content), indicator) {
			return true, "login"
		}
	}

	return false, ""
}

// Helper function for CheckProfileActivity that rates profile activity level
func RateProfileActivity(platform SocialPlatform, content string) (float64, []string) {
	activityScore := 0.0
	markers := []string{}

	// Generic activity patterns across platforms
	patterns := map[string]struct {
		regex   string
		weight  float64
		message string
	}{
		"recent_post": {
			regex:   `(?i)(posted|tweeted|shared).{1,20}(today|yesterday|hours|hour|minutes|minute|day|week)`,
			weight:  0.3,
			message: "Recent activity detected",
		},
		"post_count": {
			regex:   `(?i)(\d+),?(\d+)?\s+(posts|tweets|videos)`,
			weight:  0.2,
			message: "Multiple posts found",
		},
		"engagement": {
			regex:   `(?i)(\d+),?(\d+)?\s+(likes|comments|reactions|shares)`,
			weight:  0.2,
			message: "Engagement with content detected",
		},
		"follower_count": {
			regex:   `(?i)(\d+),?(\d+)?\s+(followers|subscribers)`,
			weight:  0.1,
			message: "Has followers",
		},
		"profile_completeness": {
			regex:   `(?i)(bio|about|description|profile).{1,50}(completed|filled)`,
			weight:  0.1,
			message: "Completed profile information",
		},
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern.regex)
		if re.MatchString(content) {
			activityScore += pattern.weight
			markers = append(markers, pattern.message)
		}
	}

	// Cap activity score at 1.0
	if activityScore > 1.0 {
		activityScore = 1.0
	}

	return activityScore, markers
}
