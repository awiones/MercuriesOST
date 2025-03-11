package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// LinkStatus represents the availability status of a resource
type LinkStatus string

const (
	StatusAvailable  LinkStatus = "AVAILABLE"
	StatusNotFound   LinkStatus = "NOT_FOUND"
	StatusRestricted LinkStatus = "RESTRICTED"
	StatusError      LinkStatus = "ERROR"
)

// ProfileURL represents a Google service URL with availability status
type ProfileURL struct {
	URL     string     `json:"url"`
	Status  LinkStatus `json:"status"`
	Message string     `json:"message,omitempty"`
}

// GoogleIDResult represents the collected data from a Google ID search
type GoogleIDResult struct {
	GoogleID      string                 `json:"google_id"`
	ProfileURLs   map[string]ProfileURL  `json:"profile_urls"`
	Contributions ContributionInfo       `json:"contributions"`
	Reviews       []ReviewInfo           `json:"reviews"`
	ArchiveData   []ArchiveInfo          `json:"archive_data"`
	Photos        []PhotoInfo            `json:"photos"`
	LastSeen      string                 `json:"last_seen"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ContributionInfo represents Google Maps contribution data
type ContributionInfo struct {
	TotalReviews    int    `json:"total_reviews"`
	TotalPhotos     int    `json:"total_photos"`
	TotalRatings    int    `json:"total_ratings"`
	ContributorRank string `json:"contributor_rank"`
	LastActivity    string `json:"last_activity"`
}

// ReviewInfo represents a Google review
type ReviewInfo struct {
	Location    string    `json:"location"`
	Rating      int       `json:"rating"`
	ReviewText  string    `json:"review_text"`
	ReviewDate  string    `json:"review_date"`
	Coordinates []float64 `json:"coordinates,omitempty"`
}

// ArchiveInfo represents archived Google+ data
type ArchiveInfo struct {
	URL         string     `json:"url"`
	ArchiveDate string     `json:"archive_date"`
	Type        string     `json:"type"`
	Status      LinkStatus `json:"status"`
}

// PhotoInfo represents a Google photo contribution
type PhotoInfo struct {
	URL         string     `json:"url"`
	Location    string     `json:"location"`
	UploadDate  string     `json:"upload_date"`
	Coordinates []float64  `json:"coordinates,omitempty"`
	Status      LinkStatus `json:"status"`
}

// HTTPClient interface for making requests (makes testing easier)
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// AnalyzeGoogleID performs comprehensive analysis of a Google ID
func AnalyzeGoogleID(ctx context.Context, googleID string) (*GoogleIDResult, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Store redirect URLs for analysis
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	return AnalyzeGoogleIDWithClient(ctx, googleID, client)
}

// AnalyzeGoogleIDWithClient performs analysis with a custom HTTP client (useful for testing)
func AnalyzeGoogleIDWithClient(ctx context.Context, googleID string, client HTTPClient) (*GoogleIDResult, error) {
	result := &GoogleIDResult{
		GoogleID:    googleID,
		ProfileURLs: make(map[string]ProfileURL),
		Metadata:    make(map[string]interface{}),
	}

	// Generate and check known profile URLs
	services := map[string]string{
		"maps":         fmt.Sprintf("https://www.google.com/maps/contrib/%s", googleID),
		"plus_archive": fmt.Sprintf("https://web.archive.org/web/*/plus.google.com/%s*", googleID),
		"photos":       fmt.Sprintf("https://get.google.com/albumarchive/%s", googleID),
		"youtube":      fmt.Sprintf("https://www.youtube.com/channel/%s", googleID),
		"play_store":   fmt.Sprintf("https://play.google.com/store/people/details?id=%s", googleID),
		"scholar":      fmt.Sprintf("https://scholar.google.com/citations?user=%s", googleID),
		"picasa":       fmt.Sprintf("https://picasaweb.google.com/%s", googleID),
		"blogger":      fmt.Sprintf("https://www.blogger.com/profile/%s", googleID),
	}

	// Check each service URL concurrently
	serviceChan := make(chan struct {
		name   string
		result ProfileURL
	})

	for name, url := range services {
		go func(name, url string) {
			status, message := checkURLStatus(ctx, client, url)
			serviceChan <- struct {
				name   string
				result ProfileURL
			}{
				name: name,
				result: ProfileURL{
					URL:     url,
					Status:  status,
					Message: message,
				},
			}
		}(name, url)
	}

	// Collect results
	for i := 0; i < len(services); i++ {
		serviceResult := <-serviceChan
		url := services[serviceResult.name]
		result.ProfileURLs[serviceResult.name] = ProfileURL{
			URL:     url,
			Status:  checkURLContent(serviceResult.result.Status, serviceResult.result.Message),
			Message: sanitizeMessage(serviceResult.result.Message),
		}
	}

	// Create channels for concurrent operations
	mapsChan := make(chan error)
	archiveChan := make(chan error)
	photoChan := make(chan error)

	// Concurrent Maps contributions analysis
	go func() {
		if result.ProfileURLs["maps"].Status == StatusAvailable {
			contributions, err := analyzeMapsContributions(ctx, client, googleID)
			if err == nil {
				result.Contributions = contributions
			}
			mapsChan <- err
		} else {
			mapsChan <- nil
		}
	}()

	// Concurrent Archive.org analysis
	go func() {
		if result.ProfileURLs["plus_archive"].Status == StatusAvailable {
			archives, err := analyzeArchiveData(ctx, client, googleID)
			if err == nil {
				result.ArchiveData = archives
			}
			archiveChan <- err
		} else {
			archiveChan <- nil
		}
	}()

	// Concurrent Photos analysis
	go func() {
		if result.ProfileURLs["photos"].Status == StatusAvailable {
			photos, err := analyzePhotoContributions(ctx, client, googleID)
			if err == nil {
				result.Photos = photos
			}
			photoChan <- err
		} else {
			photoChan <- nil
		}
	}()

	// Wait for all operations to complete
	errs := []error{
		<-mapsChan,
		<-archiveChan,
		<-photoChan,
	}

	// Check for errors
	var errStrings []string
	for _, err := range errs {
		if err != nil {
			errStrings = append(errStrings, err.Error())
		}
	}

	// Set last seen timestamp
	result.LastSeen = findLastActivity(result)

	if len(errStrings) > 0 {
		return result, fmt.Errorf("partial data collection completed with errors: %s", strings.Join(errStrings, "; "))
	}

	return result, nil
}

// checkURLStatus verifies if a URL is available, not found, or restricted
func checkURLStatus(ctx context.Context, client HTTPClient, url string) (LinkStatus, string) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return StatusError, fmt.Sprintf("Error creating request: %v", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return StatusError, fmt.Sprintf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	// Read a portion of the body for content analysis
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 8192)) // Read up to 8KB
	if err != nil {
		return StatusError, fmt.Sprintf("Error reading response: %v", err)
	}
	bodyText := string(bodyBytes)

	// Handle common status codes
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		// Need to check content for false positives
		return StatusAvailable, bodyText
	case http.StatusNotFound, http.StatusGone:
		return StatusNotFound, "Resource not found"
	case http.StatusForbidden, http.StatusUnauthorized:
		return StatusRestricted, "Access restricted"
	case http.StatusFound, http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		// Handle redirects - could be to error pages
		location := resp.Header.Get("Location")
		if strings.Contains(location, "error") || strings.Contains(location, "not-found") {
			return StatusNotFound, fmt.Sprintf("Redirected to: %s", location)
		}
		return StatusAvailable, fmt.Sprintf("Redirected to: %s", location)
	default:
		return StatusError, fmt.Sprintf("Unexpected status code: %d", resp.StatusCode)
	}
}

// checkURLContent analyzes response content to better determine status
func checkURLContent(status LinkStatus, content string) LinkStatus {
	if status != StatusAvailable {
		return status
	}

	lowerContent := strings.ToLower(content)

	// Common error indicators
	notFoundPatterns := []string{
		"not found", "doesn't exist", "no longer available",
		"couldn't find", "could not find", "404", "no results found",
		"no such user", "user not found", "profile unavailable",
	}

	restrictedPatterns := []string{
		"access denied", "forbidden", "restricted", "private",
		"sign in", "log in", "login required", "permission denied",
		"not authorized", "unauthorized", "requires authentication",
	}

	for _, pattern := range notFoundPatterns {
		if strings.Contains(lowerContent, pattern) {
			return StatusNotFound
		}
	}

	for _, pattern := range restrictedPatterns {
		if strings.Contains(lowerContent, pattern) {
			return StatusRestricted
		}
	}

	// Check for empty pages that return 200 but have no meaningful content
	if len(content) < 50 && !strings.Contains(content, googleIDPattern) {
		return StatusNotFound
	}

	return StatusAvailable
}

// sanitizeMessage removes sensitive information from error messages
func sanitizeMessage(message string) string {
	if len(message) > 100 {
		return "Content analyzed for availability"
	}
	return message
}

// Regex pattern for Google IDs
const googleIDPattern = `\d{21}`

// analyzeMapsContributions gathers Google Maps contribution data
func analyzeMapsContributions(ctx context.Context, client HTTPClient, googleID string) (ContributionInfo, error) {
	info := ContributionInfo{}

	// Construct Maps contribution URL
	url := fmt.Sprintf("https://www.google.com/maps/contrib/%s", googleID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return info, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("maps profile returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}

	bodyStr := string(body)

	// Extract review count using regex
	reviewCountRegex := regexp.MustCompile(`(\d+)\s+reviews`)
	if matches := reviewCountRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		fmt.Sscanf(matches[1], "%d", &info.TotalReviews)
	}

	// Extract photo count using regex
	photoCountRegex := regexp.MustCompile(`(\d+)\s+photos`)
	if matches := photoCountRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		fmt.Sscanf(matches[1], "%d", &info.TotalPhotos)
	}

	// Extract contributor level (Local Guide level)
	rankRegex := regexp.MustCompile(`Local Guide · Level (\d+)`)
	if matches := rankRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		info.ContributorRank = "Level " + matches[1]
	}

	// Set last activity to current time as approximation since we can't reliably get it
	info.LastActivity = time.Now().Format(time.RFC3339)

	return info, nil
}

// analyzeArchiveData checks Archive.org for Google+ history
func analyzeArchiveData(ctx context.Context, client HTTPClient, googleID string) ([]ArchiveInfo, error) {
	archives := []ArchiveInfo{}

	// Construct Archive.org API URL
	url := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=plus.google.com/%s&output=json", googleID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return archives, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return archives, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return archives, fmt.Errorf("archive.org API returned status %d", resp.StatusCode)
	}

	// Parse archive data
	var rawData [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rawData); err != nil {
		return archives, err
	}

	// The first row contains column headers, skip it
	if len(rawData) <= 1 {
		return archives, nil // No archive data found
	}

	// Process archive entries (skip header row)
	for i := 1; i < len(rawData); i++ {
		if len(rawData[i]) < 5 {
			continue // Skip invalid rows
		}

		timeStampStr := rawData[i][1]
		originalURL := rawData[i][2]
		// Removed unused mimeType variable

		// Convert timestamp to readable date
		timestamp, err := time.Parse("20060102150405", timeStampStr)
		if err != nil {
			continue // Skip invalid timestamps
		}

		archiveURL := fmt.Sprintf("https://web.archive.org/web/%s/%s", timeStampStr, originalURL)

		// Determine content type
		var contentType string
		if strings.Contains(originalURL, "/posts/") {
			contentType = "Post"
		} else if strings.Contains(originalURL, "/photos/") {
			contentType = "Photo"
		} else if strings.Contains(originalURL, "/about") {
			contentType = "Profile"
		} else {
			contentType = "Page"
		}

		// Check if this archive URL is available
		status, _ := checkURLStatus(ctx, client, archiveURL)

		archives = append(archives, ArchiveInfo{
			URL:         archiveURL,
			ArchiveDate: timestamp.Format(time.RFC3339),
			Type:        contentType,
			Status:      status,
		})
	}

	return archives, nil
}

// analyzePhotoContributions gathers Google Photos/Albums data
func analyzePhotoContributions(ctx context.Context, client HTTPClient, googleID string) ([]PhotoInfo, error) {
	photos := []PhotoInfo{}

	// Construct Google Albums archive URL
	url := fmt.Sprintf("https://get.google.com/albumarchive/%s", googleID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return photos, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return photos, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return photos, fmt.Errorf("album archive returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return photos, err
	}

	bodyStr := string(body)

	// Extract photo URLs using regex
	// This is a simple implementation - a real one would use proper HTML parsing
	photoURLRegex := regexp.MustCompile(`"(https://lh3\.googleusercontent\.com/[^"]+)"`)
	matches := photoURLRegex.FindAllStringSubmatch(bodyStr, -1)

	// Extract album titles
	albumTitleRegex := regexp.MustCompile(`<title>([^<]+)</title>`)
	albumMatch := albumTitleRegex.FindStringSubmatch(bodyStr)
	albumTitle := "Unknown Location"
	if len(albumMatch) > 1 {
		albumTitle = albumMatch[1]
		albumTitle = strings.TrimSuffix(albumTitle, " - Google Photos")
	}

	for _, match := range matches {
		if len(match) > 1 {
			photoURL := match[1]

			// Check if this photo URL is available
			status, _ := checkURLStatus(ctx, client, photoURL)

			photos = append(photos, PhotoInfo{
				URL:        photoURL,
				Location:   albumTitle,
				UploadDate: "", // Unfortunately can't reliably extract this
				Status:     status,
			})
		}
	}

	return photos, nil
}

// findLastActivity determines the most recent activity date across all data
func findLastActivity(result *GoogleIDResult) string {
	var lastDate time.Time

	// Check Contributions
	if result.Contributions.LastActivity != "" {
		if contributionDate, err := time.Parse(time.RFC3339, result.Contributions.LastActivity); err == nil {
			if contributionDate.After(lastDate) {
				lastDate = contributionDate
			}
		}
	}

	// Check Reviews
	for _, review := range result.Reviews {
		if review.ReviewDate != "" {
			if reviewDate, err := time.Parse(time.RFC3339, review.ReviewDate); err == nil {
				if reviewDate.After(lastDate) {
					lastDate = reviewDate
				}
			}
		}
	}

	// Check Photos
	for _, photo := range result.Photos {
		if photo.UploadDate != "" {
			if photoDate, err := time.Parse(time.RFC3339, photo.UploadDate); err == nil {
				if photoDate.After(lastDate) {
					lastDate = photoDate
				}
			}
		}
	}

	// Check Archive data for most recent archive
	for _, archive := range result.ArchiveData {
		if archive.ArchiveDate != "" {
			if archiveDate, err := time.Parse(time.RFC3339, archive.ArchiveDate); err == nil {
				if archiveDate.After(lastDate) {
					lastDate = archiveDate
				}
			}
		}
	}

	if lastDate.IsZero() {
		return ""
	}
	return lastDate.Format(time.RFC3339)
}

// DisplayGoogleIDResults formats and displays the Google ID analysis results
func (r *GoogleIDResult) DisplayResults() {
	fmt.Printf("\n=== Google ID Analysis Results ===\n")
	fmt.Printf("Google ID: %s\n\n", r.GoogleID)

	fmt.Println("Profile URLs:")
	for service, profile := range r.ProfileURLs {
		statusEmoji := "❓" // Unknown
		switch profile.Status {
		case StatusAvailable:
			statusEmoji = "✅" // Available
		case StatusNotFound:
			statusEmoji = "❌" // Not Found
		case StatusRestricted:
			statusEmoji = "🔒" // Restricted
		case StatusError:
			statusEmoji = "⚠️" // Error
		}
		fmt.Printf("• %s %s: %s\n", statusEmoji, strings.ReplaceAll(strings.Title(service), "_", " "), profile.URL)
	}

	if r.Contributions.TotalReviews > 0 || r.Contributions.TotalPhotos > 0 {
		fmt.Printf("\nMaps Contributions:\n")
		fmt.Printf("• Total Reviews: %d\n", r.Contributions.TotalReviews)
		fmt.Printf("• Total Photos: %d\n", r.Contributions.TotalPhotos)
		if r.Contributions.ContributorRank != "" {
			fmt.Printf("• Contributor Rank: %s\n", r.Contributions.ContributorRank)
		}
	}

	if len(r.Reviews) > 0 {
		fmt.Printf("\nRecent Reviews:\n")
		for _, review := range r.Reviews {
			fmt.Printf("• %s (%d★) - %s\n", review.Location, review.Rating, review.ReviewDate)
			if review.ReviewText != "" {
				fmt.Printf("  \"%s\"\n", review.ReviewText)
			}
		}
	}

	if len(r.ArchiveData) > 0 {
		fmt.Printf("\nArchived Data (%d results):\n", len(r.ArchiveData))
		// Limit to 5 most recent entries to avoid overwhelming output
		showCount := 5
		if len(r.ArchiveData) < showCount {
			showCount = len(r.ArchiveData)
		}
		for i := 0; i < showCount; i++ {
			archive := r.ArchiveData[i]
			statusEmoji := "✅"
			if archive.Status != StatusAvailable {
				statusEmoji = "❌"
			}
			fmt.Printf("• %s %s (%s): %s\n",
				statusEmoji,
				archive.Type,
				archive.ArchiveDate,
				archive.URL)
		}
		if len(r.ArchiveData) > showCount {
			fmt.Printf("  ...and %d more archive entries\n", len(r.ArchiveData)-showCount)
		}
	}

	if len(r.Photos) > 0 {
		fmt.Printf("\nPhotos Found (%d results):\n", len(r.Photos))
		// Limit to 5 photos to avoid overwhelming output
		showCount := 5
		if len(r.Photos) < showCount {
			showCount = len(r.Photos)
		}
		for i := 0; i < showCount; i++ {
			photo := r.Photos[i]
			statusEmoji := "✅"
			if photo.Status != StatusAvailable {
				statusEmoji = "❌"
			}
			fmt.Printf("• %s %s: %s\n",
				statusEmoji,
				photo.Location,
				photo.URL)
		}
		if len(r.Photos) > showCount {
			fmt.Printf("  ...and %d more photos\n", len(r.Photos)-showCount)
		}
	}

	if r.LastSeen != "" {
		fmt.Printf("\nLast Seen: %s\n", r.LastSeen)
	}

	fmt.Println("\nLegend:")
	fmt.Println("✅ Available   ❌ Not Found   🔒 Restricted   ⚠️ Error")
}

// ExportJSON exports the results to JSON
func (r *GoogleIDResult) ExportJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
