package osint

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// ValidationResult stores the validation status and details
type ValidationResult struct {
	IsValid     bool
	Confidence  float64
	Markers     []string
	StatusCode  int
	ErrorReason string
}

// ValidateProfile performs additional checks to verify if a profile is genuine
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

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		result.ErrorReason = fmt.Sprintf("Invalid status code: %d", resp.StatusCode)
		return result
	}

	// Parse HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		result.ErrorReason = fmt.Sprintf("Error parsing HTML: %v", err)
		return result
	}

	// Perform platform-specific validation
	switch platform.Name {
	case "Twitter":
		return validateTwitterProfile(doc)
	case "Instagram":
		return validateInstagramProfile(doc)
	case "LinkedIn":
		return validateLinkedInProfile(doc)
	case "GitHub":
		return validateGitHubProfile(doc)
	case "Facebook":
		return validateFacebookProfile(doc)
	default:
		return validateGenericProfile(doc, platform)
	}
}

func validateTwitterProfile(doc *goquery.Document) ValidationResult {
	result := ValidationResult{
		Markers: make([]string, 0),
	}

	// Check for Twitter-specific elements
	if doc.Find("[data-testid='UserName']").Length() > 0 {
		result.Markers = append(result.Markers, "Has username element")
		result.Confidence += 0.3
	}

	if doc.Find("[data-testid='UserAvatar']").Length() > 0 {
		result.Markers = append(result.Markers, "Has avatar")
		result.Confidence += 0.2
	}

	if doc.Find("[data-testid='tweet']").Length() > 0 {
		result.Markers = append(result.Markers, "Has tweets")
		result.Confidence += 0.3
	}

	if doc.Find("[data-testid='UserProfileHeader_Items']").Length() > 0 {
		result.Markers = append(result.Markers, "Has profile header")
		result.Confidence += 0.2
	}

	result.IsValid = result.Confidence >= 0.7
	return result
}

func validateInstagramProfile(doc *goquery.Document) ValidationResult {
	result := ValidationResult{
		Markers: make([]string, 0),
	}

	// Check for Instagram-specific elements
	if doc.Find("header").Length() > 0 {
		result.Markers = append(result.Markers, "Has profile header")
		result.Confidence += 0.3
	}

	if doc.Find("header img").Length() > 0 {
		result.Markers = append(result.Markers, "Has profile picture")
		result.Confidence += 0.2
	}

	if doc.Find("article").Length() > 0 {
		result.Markers = append(result.Markers, "Has posts")
		result.Confidence += 0.3
	}

	if doc.Find(".biography").Length() > 0 {
		result.Markers = append(result.Markers, "Has biography")
		result.Confidence += 0.2
	}

	result.IsValid = result.Confidence >= 0.6
	return result
}

func validateLinkedInProfile(doc *goquery.Document) ValidationResult {
	result := ValidationResult{
		Markers: make([]string, 0),
	}

	// Check for LinkedIn-specific elements
	if doc.Find(".pv-top-card").Length() > 0 {
		result.Markers = append(result.Markers, "Has profile card")
		result.Confidence += 0.3
	}

	if doc.Find(".experience-section").Length() > 0 {
		result.Markers = append(result.Markers, "Has experience section")
		result.Confidence += 0.3
	}

	if doc.Find(".education-section").Length() > 0 {
		result.Markers = append(result.Markers, "Has education section")
		result.Confidence += 0.2
	}

	if doc.Find(".profile-photo-edit__preview").Length() > 0 {
		result.Markers = append(result.Markers, "Has profile photo")
		result.Confidence += 0.2
	}

	result.IsValid = result.Confidence >= 0.6
	return result
}

func validateGitHubProfile(doc *goquery.Document) ValidationResult {
	result := ValidationResult{
		Markers: make([]string, 0),
	}

	// Check for GitHub-specific elements
	if doc.Find(".vcard-avatar").Length() > 0 {
		result.Markers = append(result.Markers, "Has avatar")
		result.Confidence += 0.2
	}

	if doc.Find(".vcard-names").Length() > 0 {
		result.Markers = append(result.Markers, "Has name section")
		result.Confidence += 0.2
	}

	if doc.Find(".js-yearly-contributions").Length() > 0 {
		result.Markers = append(result.Markers, "Has contribution graph")
		result.Confidence += 0.3
	}

	if doc.Find(".pinned-items-list").Length() > 0 {
		result.Markers = append(result.Markers, "Has pinned repositories")
		result.Confidence += 0.3
	}

	result.IsValid = result.Confidence >= 0.5
	return result
}

func validateFacebookProfile(doc *goquery.Document) ValidationResult {
	result := ValidationResult{
		Markers: make([]string, 0),
	}

	// Check for Facebook-specific elements
	if doc.Find("[data-pagelet='ProfileActions']").Length() > 0 {
		result.Markers = append(result.Markers, "Has profile actions")
		result.Confidence += 0.3
	}

	if doc.Find("[data-pagelet='ProfileTimeline']").Length() > 0 {
		result.Markers = append(result.Markers, "Has timeline")
		result.Confidence += 0.3
	}

	if doc.Find("[data-pagelet='ProfilePhoto']").Length() > 0 {
		result.Markers = append(result.Markers, "Has profile photo")
		result.Confidence += 0.2
	}

	if doc.Find("[data-pagelet='ProfileTilesBio']").Length() > 0 {
		result.Markers = append(result.Markers, "Has bio section")
		result.Confidence += 0.2
	}

	result.IsValid = result.Confidence >= 0.6
	return result
}

func validateGenericProfile(doc *goquery.Document, platform SocialPlatform) ValidationResult {
	result := ValidationResult{
		Markers: make([]string, 0),
	}

	// Check existence markers
	html, _ := doc.Html()
	for _, marker := range platform.ExistMarkers {
		if strings.Contains(html, marker) {
			result.Markers = append(result.Markers, fmt.Sprintf("Found marker: %s", marker))
			result.Confidence += 0.3
		}
	}

	// Check for non-existence markers
	for _, marker := range platform.NotExistMarkers {
		if strings.Contains(html, marker) {
			result.Markers = append(result.Markers, fmt.Sprintf("Found negative marker: %s", marker))
			result.Confidence -= 0.4
		}
	}

	// Check basic profile elements using platform selectors
	if platform.NameSelector != "" && doc.Find(platform.NameSelector).Length() > 0 {
		result.Markers = append(result.Markers, "Has name element")
		result.Confidence += 0.2
	}

	if platform.AvatarSelector != "" && doc.Find(platform.AvatarSelector).Length() > 0 {
		result.Markers = append(result.Markers, "Has avatar element")
		result.Confidence += 0.2
	}

	if platform.BioSelector != "" && doc.Find(platform.BioSelector).Length() > 0 {
		result.Markers = append(result.Markers, "Has bio element")
		result.Confidence += 0.2
	}

	result.IsValid = result.Confidence >= 0.5
	return result
}
