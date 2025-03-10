package osint

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"context"
	"runtime"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/awion/MercuriesOST/public/variations"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// SocialPlatform represents a social media platform to search
type SocialPlatform struct {
	Name                string
	URL                 string
	ProfilePattern      string
	ExistMarkers        []string
	NotExistMarkers     []string
	NameSelector        string
	BioSelector         string
	AvatarSelector      string
	FollowersSelector   string
	JoinDateSelector    string
	LocationSelector    string
	ActivitySelector    string
	ConnectionsSelector string
}

// ProfileResult stores the result of a profile search
type ProfileResult struct {
	Platform       string   `json:"platform"`
	URL            string   `json:"url"`
	Exists         bool     `json:"exists"`
	Username       string   `json:"username"`
	FullName       string   `json:"full_name,omitempty"`
	Bio            string   `json:"bio,omitempty"`
	FollowerCount  int      `json:"follower_count,omitempty"`
	JoinDate       string   `json:"join_date,omitempty"`
	Avatar         string   `json:"avatar_url,omitempty"`
	Location       string   `json:"location,omitempty"`
	Connections    []string `json:"connections,omitempty"`
	RecentActivity []string `json:"recent_activity,omitempty"`
	Insights       []string `json:"insights,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// SocialMediaResults stores all results from a search
type SocialMediaResults struct {
	Query         string          `json:"query"`
	Timestamp     string          `json:"timestamp"`
	ProfilesFound int             `json:"profiles_found"`
	Profiles      []ProfileResult `json:"profiles"`
}

// workItem represents a single work unit for processing
type workItem struct {
	platform SocialPlatform
	term     string
}

// Common social media platforms to check with enhanced selectors
var platforms = []SocialPlatform{
	{
		Name:                "Twitter",
		URL:                 "https://twitter.com/",
		ProfilePattern:      "%s",
		ExistMarkers:        []string{"profile-picture", "profile-card"},
		NotExistMarkers:     []string{"This account doesn't exist", "User not found"},
		NameSelector:        "[data-testid='UserName'], .fullname",
		BioSelector:         "[data-testid='UserDescription'], .bio",
		AvatarSelector:      "[data-testid='UserAvatar'] img, .profile-picture",
		FollowersSelector:   "[data-testid='UserProfileHeader_Items'] span, .followers-count",
		JoinDateSelector:    "[data-testid='UserProfileHeader_Items'] span:contains('Joined'), .join-date",
		LocationSelector:    "[data-testid='UserLocation'], .location",
		ActivitySelector:    "[data-testid='tweet'], .timeline-item",
		ConnectionsSelector: ".follows-recommendations, .follows-you",
	},
	{
		Name:                "Instagram",
		URL:                 "https://www.instagram.com/",
		ProfilePattern:      "%s/",
		ExistMarkers:        []string{"profile-picture", "biography"},
		NotExistMarkers:     []string{"Page Not Found", "Sorry, this page isn't available"},
		NameSelector:        "header h1, .fullname",
		BioSelector:         "header h1 ~ div, .biography",
		AvatarSelector:      "header img, .profile-picture",
		FollowersSelector:   "ul li span, .followers",
		JoinDateSelector:    "", // Instagram doesn't show join date
		LocationSelector:    "", // Instagram doesn't consistently show location
		ActivitySelector:    "article, .post",
		ConnectionsSelector: ".followed-by, .follows-you",
	},
	{
		Name:                "Facebook",
		URL:                 "https://www.facebook.com/",
		ProfilePattern:      "%s",
		ExistMarkers:        []string{"profile-picture", "cover-photo"},
		NotExistMarkers:     []string{"Page Not Found", "content isn't available"},
		NameSelector:        "h1, .fullname",
		BioSelector:         "[data-pagelet='ProfileTilesBio'], .bio",
		AvatarSelector:      "[data-pagelet='ProfilePhoto'] img, .profile-picture",
		FollowersSelector:   "[data-pagelet='ProfileActions'] span, .followers",
		JoinDateSelector:    "", // Facebook doesn't consistently show join date
		LocationSelector:    "[data-pagelet='ProfileTilesLocation'], .location",
		ActivitySelector:    "[data-pagelet='ProfileTimeline'] article, .timeline-item",
		ConnectionsSelector: "[data-pagelet='ProfileFriendsCard'], .friend-card",
	},
	{
		Name:                "LinkedIn",
		URL:                 "https://www.linkedin.com/in/",
		ProfilePattern:      "%s/",
		ExistMarkers:        []string{"profile-picture", "experience"},
		NotExistMarkers:     []string{"Page Not Found", "This page doesn't exist"},
		NameSelector:        ".pv-top-card--list h1, .profile-name",
		BioSelector:         ".pv-about-section, .bio",
		AvatarSelector:      ".pv-top-card__photo img, .profile-picture",
		FollowersSelector:   ".pv-top-card--list-bullet li, .follower-count",
		JoinDateSelector:    "", // LinkedIn doesn't prominently show join date
		LocationSelector:    ".pv-top-card--list-bullet li, .location",
		ActivitySelector:    ".activity-section article, .activity-item",
		ConnectionsSelector: ".pv-browsemap-section__member, .connection-card",
	},
	{
		Name:                "GitHub",
		URL:                 "https://github.com/",
		ProfilePattern:      "%s",
		ExistMarkers:        []string{"avatar", "pinned-items-container"},
		NotExistMarkers:     []string{"404", "Not Found"},
		NameSelector:        "span.p-name, .fullname",
		BioSelector:         "div.p-note, .bio",
		AvatarSelector:      "img.avatar, .profile-picture",
		FollowersSelector:   ".js-profile-editable-area a[href*='followers'], .followers",
		JoinDateSelector:    "relative-time, .join-date",
		LocationSelector:    "li[itemprop='homeLocation'], .location",
		ActivitySelector:    ".contribution-activity-listing article, .activity-item",
		ConnectionsSelector: ".js-org-members, .connection-card",
	},
	{
		Name:                "Reddit",
		URL:                 "https://www.reddit.com/user/",
		ProfilePattern:      "%s",
		ExistMarkers:        []string{"UserProfileHeader", "karma"},
		NotExistMarkers:     []string{"page not found", "Sorry, nobody on Reddit goes by that name"},
		NameSelector:        "h4._2xvlm, .fullname",
		BioSelector:         "div._1zPvgKHteTOub9dKkvrOl4, .bio",
		AvatarSelector:      "img._2bLCGrtCCJIMNCZgmAMZFM, .profile-picture",
		FollowersSelector:   "span._3uK2I0hi3JFTKnMUFHD2Pd, .followers",
		JoinDateSelector:    "span:contains('Created'), .join-date",
		LocationSelector:    "", // Reddit doesn't show location
		ActivitySelector:    "div.Profile__posts article, .post",
		ConnectionsSelector: "", // Reddit doesn't show connections prominently
	},
	{
		Name:                "TikTok",
		URL:                 "https://www.tiktok.com/@",
		ProfilePattern:      "%s",
		ExistMarkers:        []string{"avatar", "following-count"},
		NotExistMarkers:     []string{"Couldn't find this account", "Page not available"},
		NameSelector:        "h1.share-title, .fullname",
		BioSelector:         "h2.share-desc, .bio",
		AvatarSelector:      "img.avatar, .profile-picture",
		FollowersSelector:   "strong.count-infos, .followers",
		JoinDateSelector:    "", // TikTok doesn't show join date
		LocationSelector:    "", // TikTok doesn't consistently show location
		ActivitySelector:    "div.video-feed-item, .post",
		ConnectionsSelector: "", // TikTok doesn't show connections prominently
	},
}

// Configure scanning parameters - optimized for low-end systems
const (
	maxConcurrentScans = 5               // Reduced from 10 to prevent overwhelming
	scanRateLimit      = 10              // Reduced from 20 to prevent rate limits
	batchSize          = 3               // Reduced batch size for memory efficiency
	maxRetries         = 2               // Reduced retries to save resources
	updateInterval     = 2 * time.Second // Reduced update frequency
	maxWorkers         = 3               // Maximum number of workers for low-end systems
)

// Add this struct for rate tracking
type rateTracker struct {
	mu              sync.Mutex
	count           int
	lastCount       int
	lastUpdate      time.Time
	currentRate     float64
	currentPlatform string // Add this field
}

func (rt *rateTracker) update() {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	duration := now.Sub(rt.lastUpdate).Seconds()
	if duration >= 1 { // Update rate every second
		rt.currentRate = float64(rt.count-rt.lastCount) / duration
		rt.lastCount = rt.count
		rt.lastUpdate = now
	}
}

func (rt *rateTracker) increment() {
	rt.mu.Lock()
	rt.count++
	rt.mu.Unlock()
}

func (rt *rateTracker) getRate() float64 {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.currentRate
}

// Add method to update current platform
func (rt *rateTracker) setCurrentPlatform(platform string) {
	rt.mu.Lock()
	rt.currentPlatform = platform
	rt.mu.Unlock()
}

// Add memory management
type memoryManager struct {
	mu       sync.Mutex
	maxItems int
	items    []ProfileResult
}

func newMemoryManager(maxItems int) *memoryManager {
	return &memoryManager{
		maxItems: maxItems,
		items:    make([]ProfileResult, 0, maxItems),
	}
}

func (mm *memoryManager) add(item ProfileResult) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// If we're at capacity, write to disk
	if len(mm.items) >= mm.maxItems {
		mm.flush()
	}
	mm.items = append(mm.items, item)
}

func (mm *memoryManager) flush() {
	// Write current items to temporary file
	if len(mm.items) > 0 {
		tempFile := fmt.Sprintf("dump/temp_%d.json", time.Now().UnixNano())
		data, _ := json.Marshal(mm.items)
		ioutil.WriteFile(tempFile, data, 0644)
		mm.items = mm.items[:0] // Clear slice while preserving capacity
	}
}

// Update hardware acceleration settings with combined constants
const (
	// Hardware acceleration settings for GPU
	gpuBatchSize  = 500 // Increased from 200
	gpuMaxWorkers = 100 // Increased from 50
	gpuMaxConns   = 200 // Increased from 100

	// Hardware acceleration settings for TPU
	tpuBatchSize  = 1000 // Increased from 500
	tpuMaxWorkers = 200  // Increased from 100
	tpuMaxConns   = 400  // Increased from 200

	// Default acceleration for systems without GPU/TPU
	defaultBatchSize  = 50
	defaultMaxWorkers = 20
	defaultMaxConns   = 50
)

// Add accelerator capabilities
type hardwareAccelerator struct {
	hasGPU     bool
	hasTPU     bool
	deviceName string
	maxBatch   int
	maxWorkers int
	maxConns   int
}

func detectHardware() hardwareAccelerator {
	acc := hardwareAccelerator{
		maxBatch:   defaultBatchSize,  // Increased default batch
		maxWorkers: defaultMaxWorkers, // Increased default workers
		maxConns:   defaultMaxConns,   // Increased default connections
	}

	// Check for NVIDIA GPU
	if _, err := os.Stat("/dev/nvidia0"); err == nil {
		acc.hasGPU = true
		acc.deviceName = "NVIDIA GPU"
		acc.maxBatch = gpuBatchSize
		acc.maxWorkers = gpuMaxWorkers
		acc.maxConns = gpuMaxConns
	}

	// Check for Google TPU
	if _, err := os.Stat("/dev/accel0"); err == nil {
		acc.hasTPU = true
		acc.deviceName = "Google TPU"
		acc.maxBatch = tpuBatchSize
		acc.maxWorkers = tpuMaxWorkers
		acc.maxConns = tpuMaxConns
	}

	return acc
}

// SearchProfilesSequentially searches for a username across platforms one by one
func SearchProfilesSequentially(username string, outputPath string, verbose bool) (*SocialMediaResults, error) {
	// Detect hardware capabilities
	acc := detectHardware()
	if verbose && (acc.hasGPU || acc.hasTPU) {
		fmt.Printf("Hardware acceleration enabled: %s (Batch: %d, Workers: %d)\n",
			acc.deviceName, acc.maxBatch, acc.maxWorkers)
	}

	// Initialize optimized transport
	transport := &http.Transport{
		MaxIdleConns:        acc.maxConns,
		MaxIdleConnsPerHost: acc.maxConns,
		MaxConnsPerHost:     acc.maxConns,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
		WriteBufferSize:     64 * 1024, // Increased buffer size
		ReadBufferSize:      64 * 1024,
	}

	// Create connection pool with hardware-optimized settings
	connPool := &sync.Pool{
		New: func() interface{} {
			return &http.Client{
				Timeout:   time.Second * 30, // Increased timeout
				Transport: transport,
			}
		},
	}

	// Optimize rate limiter based on hardware
	limiter := rate.NewLimiter(rate.Limit(acc.maxWorkers*2), acc.maxWorkers)

	// Initialize results only once at the start
	results := &SocialMediaResults{
		Query:     username,
		Timestamp: time.Now().Format(time.RFC3339),
		Profiles:  make([]ProfileResult, 0),
	}

	// Get variations
	searchTerms := variations.GetNameVariations(username)

	if verbose {
		fmt.Printf("Generated %d variations, saved to dump/%s-variations.json\n",
			len(searchTerms),
			strings.ToLower(strings.ReplaceAll(username, " ", "-")))
	}

	// Initialize rate limiter and error group
	limiter = rate.NewLimiter(rate.Limit(scanRateLimit), maxConcurrentScans)
	g, ctx := errgroup.WithContext(context.Background())

	// Create result channels
	resultsChan := make(chan ProfileResult, len(platforms)*len(searchTerms))
	errorsChan := make(chan error, maxConcurrentScans)

	// Initialize work pool
	var wg sync.WaitGroup

	// Create a single work channel
	workChan := make(chan workItem, acc.maxWorkers*2)

	// Create rate tracker
	tracker := &rateTracker{lastUpdate: time.Now()}
	memManager := newMemoryManager(100) // Create memory manager instance

	// Progress bar setup with rate display
	totalOperations := len(platforms) * len(searchTerms)
	bar := progressbar.NewOptions(totalOperations,
		progressbar.OptionSetDescription("Starting scan..."),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	// Start workers before feeding work items
	for i := 0; i < acc.maxWorkers; i++ {
		wg.Add(1)
		g.Go(func() error {
			defer wg.Done()
			client := connPool.Get().(*http.Client)
			defer connPool.Put(client)

			for work := range workChan {
				tracker.setCurrentPlatform(work.platform.Name)

				if err := limiter.Wait(ctx); err != nil {
					return err
				}

				result := processSingleProfile(client, work.platform, work.term)
				if result.Exists {
					resultsChan <- result
				}

				tracker.increment()
				bar.Add(1)
			}
			return nil
		})
	}

	// Feed work items after workers are started
	go func() {
		for _, platform := range platforms {
			for _, term := range searchTerms {
				select {
				case workChan <- workItem{platform: platform, term: term}:
				case <-ctx.Done():
					return
				}
			}
		}
		close(workChan)
	}()

	// Start rate display updater with platform information
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(updateInterval)
				tracker.update()
				platform := tracker.currentPlatform
				if platform != "" {
					bar.Describe(fmt.Sprintf("[cyan]Scanning %s[reset] (%.1f profiles/s)",
						platform, tracker.getRate()))
				}
			}
		}
	}()

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
		close(errorsChan)
	}()

	// Wait for error group completion
	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("worker error: %v", err)
	}

	// Collect results
	processedProfiles := make(map[string]bool)
	for result := range resultsChan {
		// Skip duplicate profiles
		if processedProfiles[result.URL] {
			continue
		}
		processedProfiles[result.URL] = true

		if result.Exists {
			results.ProfilesFound++
			memManager.add(result)  // Now memManager is defined
			results.Profiles = append(results.Profiles, result)

			if verbose {
				printProfileDetails(&result)
			}
		}
	}

	// Flush any remaining results before returning
	memManager.flush()  // Now memManager is defined

	// Check for errors
	if len(errorsChan) > 0 {
		return results, fmt.Errorf("encountered %d errors during scanning", len(errorsChan))
	}

	// Sort profiles by platform name for consistent output
	sort.Slice(results.Profiles, func(i, j int) bool {
		return results.Profiles[i].Platform < results.Profiles[j].Platform
	})

	// Save results
	if outputPath != "" {
		if err := saveResults(results, outputPath); err != nil {
			return results, fmt.Errorf("error saving results: %v", err)
		}
	}

	return results, nil
}

// Update processSingleProfile to remove verbose parameter in checkProfile call
func processSingleProfile(client *http.Client, platform SocialPlatform, term string) ProfileResult {
	var result ProfileResult

	for retry := 0; retry < maxRetries; retry++ {
		urlTerm := strings.ToLower(strings.ReplaceAll(term, " ", ""))
		profileURL := platform.URL + fmt.Sprintf(platform.ProfilePattern, urlTerm)

		result = checkProfile(client, platform, profileURL, term) // Remove verbose parameter
		if result.Error == "" {
			break
		}

		time.Sleep(time.Second * time.Duration(retry+1))
	}

	return result
}

// Remove verbose parameter from function signature
func checkProfile(client *http.Client, platform SocialPlatform, url string, username string) ProfileResult {
	result := ProfileResult{
		Platform:       platform.Name,
		URL:            url,
		Username:       username,
		Exists:         false,
		Connections:    []string{},
		RecentActivity: []string{},
		Insights:       []string{},
	}

	// Validate the profile
	validation := ValidateProfile(client, platform, url, "")

	if validation.StatusCode != 200 {
		result.Error = fmt.Sprintf("HTTP Status: %d - %s", validation.StatusCode, validation.ErrorReason)
		return result
	}

	if validation.IsValid {
		result.Exists = true
		result.Insights = append(result.Insights, fmt.Sprintf("Profile validation confidence: %.2f", validation.Confidence))
		for _, marker := range validation.Markers {
			result.Insights = append(result.Insights, fmt.Sprintf("Validation marker: %s", marker))
		}

		// Extract profile information using platform-specific selectors
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			result.Error = err.Error()
			return result
		}

		// Set a realistic User-Agent
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

		resp, err := client.Do(req)
		if err != nil {
			result.Error = err.Error()
			return result
		}
		defer resp.Body.Close()

		// Parse the HTML response
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			result.Error = err.Error()
			return result
		}

		// Extract profile information
		extractProfileInfo(doc, &result, platform)
		extractRecentActivity(doc, &result, platform)
		extractConnections(doc, &result, platform)

		// Add insights after extracting profile information
		extractInsights(&result)
	}

	return result
}

// Helper function to print profile details
func printProfileDetails(result *ProfileResult) {
	fmt.Printf("  Username: %s\n", result.Username)
	if result.FullName != "" {
		fmt.Printf("  Full Name: %s\n", result.FullName)
	}
	if result.Bio != "" {
		fmt.Printf("  Bio: %s\n", result.Bio)
	}
	if result.FollowerCount > 0 {
		fmt.Printf("  Followers: %d\n", result.FollowerCount)
	}
	if result.Location != "" {
		fmt.Printf("  Location: %s\n", result.Location)
	}
	if len(result.Insights) > 0 {
		fmt.Println("  Insights:")
		for _, insight := range result.Insights {
			fmt.Printf("   - %s\n", insight)
		}
	}
}

// extractProfileInfo extracts detailed profile information
func extractProfileInfo(doc *goquery.Document, result *ProfileResult, platform SocialPlatform) {
	// Extract full name
	if platform.NameSelector != "" {
		doc.Find(platform.NameSelector).Each(func(i int, s *goquery.Selection) {
			if result.FullName == "" && s.Text() != "" {
				result.FullName = cleanText(s.Text())
			}
		})
	}

	// Extract bio
	if platform.BioSelector != "" {
		doc.Find(platform.BioSelector).Each(func(i int, s *goquery.Selection) {
			if result.Bio == "" && s.Text() != "" {
				result.Bio = cleanText(s.Text())
			}
		})
	}

	// Extract avatar URL
	if platform.AvatarSelector != "" {
		doc.Find(platform.AvatarSelector).Each(func(i int, s *goquery.Selection) {
			if result.Avatar == "" {
				if src, exists := s.Attr("src"); exists {
					result.Avatar = src
				}
			}
		})
	}

	// Extract follower count
	if platform.FollowersSelector != "" {
		doc.Find(platform.FollowersSelector).Each(func(i int, s *goquery.Selection) {
			text := s.Text()
			if strings.Contains(strings.ToLower(text), "follower") {
				// Extract numbers from the text
				re := regexp.MustCompile(`(\d+(?:[,.]\d+)?)`)
				matches := re.FindStringSubmatch(text)
				if len(matches) > 0 {
					// Remove commas and convert to int
					numStr := strings.ReplaceAll(matches[1], ",", "")
					numStr = strings.ReplaceAll(numStr, ".", "")
					var num int
					fmt.Sscanf(numStr, "%d", &num)
					result.FollowerCount = num
				}
			}
		})
	}

	// Extract join date
	if platform.JoinDateSelector != "" {
		doc.Find(platform.JoinDateSelector).Each(func(i int, s *goquery.Selection) {
			text := s.Text()
			if strings.Contains(strings.ToLower(text), "join") ||
				strings.Contains(strings.ToLower(text), "creat") || // Fixed from contains to Contains
				s.Is("relative-time") {
				// Save the join date text or timestamp attribute
				if timestamp, exists := s.Attr("datetime"); exists {
					result.JoinDate = timestamp
				} else {
					result.JoinDate = cleanText(text)
				}
			}
		})
	}

	// Extract location
	if platform.LocationSelector != "" {
		doc.Find(platform.LocationSelector).Each(func(i int, s *goquery.Selection) {
			if result.Location == "" && s.Text() != "" {
				result.Location = cleanText(s.Text())
			}
		})
	}

	// Add confidence score for profile matching
	confidenceScore := 0
	if result.FullName != "" {
		confidenceScore += 20
	}
	if result.Bio != "" {
		confidenceScore += 20
	}
	if result.Avatar != "" {
		confidenceScore += 20
	}
	if result.FollowerCount > 0 {
		confidenceScore += 20
	}
	if result.Location != "" {
		confidenceScore += 20
	}

	result.Insights = append(result.Insights, fmt.Sprintf("Profile match confidence: %d%%", confidenceScore))
}

// extractRecentActivity extracts recent posts or activities
func extractRecentActivity(doc *goquery.Document, result *ProfileResult, platform SocialPlatform) {
	if platform.ActivitySelector == "" {
		return
	}

	doc.Find(platform.ActivitySelector).Each(func(i int, s *goquery.Selection) {
		// Limit to 5 recent activities
		if i >= 5 {
			return
		}

		// Extract text content
		text := cleanText(s.Text())

		// Truncate if too long
		if len(text) > 100 {
			text = text[:97] + "..."
		}

		// Only add if not empty
		if text != "" {
			result.RecentActivity = append(result.RecentActivity, text)
		}
	})
}

// extractConnections extracts connections like followers, friends
func extractConnections(doc *goquery.Document, result *ProfileResult, platform SocialPlatform) {
	if platform.ConnectionsSelector == "" {
		return
	}

	doc.Find(platform.ConnectionsSelector).Each(func(i int, s *goquery.Selection) {
		// Limit to 5 connections
		if i >= 5 {
			return
		}

		// Extract text content
		text := cleanText(s.Text())

		// Truncate if too long
		if len(text) > 50 {
			text = text[:47] + "..."
		}

		// Only add if not empty
		if text != "" {
			result.Connections = append(result.Connections, text)
		}
	})
}

// extractInsights analyzes the profile data to generate insights
func extractInsights(result *ProfileResult) {
	// Only generate insights for profiles that exist
	if !result.Exists {
		return
	}

	// Check for professional presence
	if result.Platform == "LinkedIn" || result.Platform == "GitHub" {
		result.Insights = append(result.Insights, "Has professional online presence")
	}

	// Check for social influence
	if result.FollowerCount > 1000 {
		result.Insights = append(result.Insights, fmt.Sprintf("Social influence: %d+ followers on %s", result.FollowerCount, result.Platform))
	}

	// Check for active engagement
	if len(result.RecentActivity) > 2 {
		result.Insights = append(result.Insights, fmt.Sprintf("Active on %s with recent posts", result.Platform))
	}

	// Check for bio keywords
	if result.Bio != "" {
		bioLower := strings.ToLower(result.Bio)

		// Professional keywords
		professionalKeywords := []string{"engineer", "developer", "designer", "manager", "director", "founder",
			"ceo", "cto", "professional", "specialist", "expert", "consultant"}

		for _, keyword := range professionalKeywords {
			if strings.Contains(bioLower, keyword) {
				result.Insights = append(result.Insights, fmt.Sprintf("Professional role: Mentions being a %s", keyword))
				break
			}
		}

		// Interest keywords
		interestKeywords := []string{"music", "art", "travel", "tech", "technology", "sports", "gaming",
			"photography", "writing", "reading", "cooking", "fitness"}

		for _, keyword := range interestKeywords {
			if strings.Contains(bioLower, keyword) {
				result.Insights = append(result.Insights, fmt.Sprintf("Interest: Mentions %s", keyword))
				break
			}
		}
	}
}

// cleanText removes extra whitespace and cleans up text
func cleanText(text string) string {
	// Replace newlines with spaces
	text = strings.ReplaceAll(text, "\n", " ")

	// Replace multiple spaces with a single space
	re := regexp.MustCompile(`\s+`)
	text = re.ReplaceAllString(text, " ")

	// Trim whitespace
	return strings.TrimSpace(text)
}

// saveResults saves the search results to a JSON file
func saveResults(results *SocialMediaResults, outputPath string) error {
	resultsJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(outputPath, resultsJSON, 0644)
}

// Add these helper functions
func getSystemMemory() uint64 {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return memStats.Sys
}

func calculateOptimalWorkers(systemMemory uint64) int {
	// Base calculation on available system memory
	// Allow roughly 50MB per worker
	workersBasedOnMemory := int(systemMemory / (50 * 1024 * 1024))
	if workersBasedOnMemory < 1 {
		return 1
	}
	return workersBasedOnMemory
}
