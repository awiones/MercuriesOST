package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/awion/MercuriesOST/public/assets/emailvalidator"
	"github.com/fatih/color"
)

// EmailAnalysisResult holds the comprehensive data structure for email intelligence
type EmailAnalysisResult struct {
	Email           string                 `json:"email"`
	ValidFormat     bool                   `json:"valid_format"`
	Username        string                 `json:"username"`
	Domain          string                 `json:"domain"`
	CommonServices  []string               `json:"common_services"`
	PatternAnalysis PatternAnalysis        `json:"pattern_analysis"`
	SecurityInfo    SecurityInfo           `json:"security_info"`
	DomainInfo      DomainInfo             `json:"domain_info"`
	SocialProfiles  []SocialProfile        `json:"social_profiles"`
	GmailSpecific   GmailSpecificInfo      `json:"gmail_specific,omitempty"`
	OnlinePresence  OnlinePresenceInfo     `json:"online_presence"`
	Metadata        map[string]interface{} `json:"metadata"`
	SearchTimestamp string                 `json:"search_timestamp"`
}

// PatternAnalysis contains pattern-related information for the email
type PatternAnalysis struct {
	IsBusinessEmail     bool     `json:"is_business_email"`
	Patterns            []string `json:"patterns"`
	IdentityComposition []string `json:"identity_composition"`
}

// SecurityInfo contains security-related information for the email
type SecurityInfo struct {
	BreachCount       int                    `json:"breach_count"`
	BreachDetails     []BreachDetail         `json:"breach_details"`
	LeakSources       []string               `json:"leak_sources"`
	ExposedPasswords  int                    `json:"exposed_passwords"`
	ExposedDataTypes  []string               `json:"exposed_data_types"`
	LastBreachDate    string                 `json:"last_breach_date"`
	RiskScore         int                    `json:"risk_score"`
	RecentActivityIPs []string               `json:"recent_activity_ips"`
	Metadata          map[string]interface{} `json:"metadata"`
}

// BreachDetail provides structured information about a specific breach
type BreachDetail struct {
	BreachName      string   `json:"breach_name"`
	BreachDate      string   `json:"breach_date"`
	CompromisedData []string `json:"compromised_data"`
	Description     string   `json:"description"`
	IsSensitive     bool     `json:"is_sensitive"`
	IsVerified      bool     `json:"is_verified"`
}

// DomainInfo contains information about the email domain
type DomainInfo struct {
	Registrar         string     `json:"registrar"`
	CreationDate      string     `json:"creation_date"`
	ExpiryDate        string     `json:"expiry_date"`
	MXRecords         []MXRecord `json:"mx_records"`
	SPFRecord         string     `json:"spf_record"`
	DMARCRecord       string     `json:"dmarc_record"`
	DKIMRecords       []string   `json:"dkim_records"`
	IPAddresses       []string   `json:"ip_addresses"`
	GeoIPInfo         GeoIPInfo  `json:"geoip_info"`
	DNSHealthScore    int        `json:"dns_health_score"`
	EmailQualityScore int        `json:"email_quality_score"`
}

// MXRecord provides detailed information about an MX record
type MXRecord struct {
	Host     string `json:"host"`
	Priority int    `json:"priority"`
	Provider string `json:"provider"`
}

// GeoIPInfo provides geographical information about IPs
type GeoIPInfo struct {
	Country     string    `json:"country"`
	Region      string    `json:"region"`
	City        string    `json:"city"`
	Coordinates []float64 `json:"coordinates"`
	ISP         string    `json:"isp"`
	ASN         string    `json:"asn"`
}

// SocialProfile represents a social media profile linked to an email
type SocialProfile struct {
	Platform    string                 `json:"platform"`
	URL         string                 `json:"url"`
	Username    string                 `json:"username"`
	DisplayName string                 `json:"display_name,omitempty"`
	Bio         string                 `json:"bio,omitempty"`
	ProfilePic  string                 `json:"profile_pic,omitempty"`
	Verified    bool                   `json:"verified"`
	LastActive  string                 `json:"last_active,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// GmailSpecificInfo contains Gmail-specific information
type GmailSpecificInfo struct {
	GoogleServices      []GoogleService `json:"google_services"`
	IsGoogleWorkspace   bool            `json:"is_google_workspace"`
	WorkspaceDomain     string          `json:"workspace_domain,omitempty"`
	AccountCreationDate string          `json:"account_creation_date,omitempty"`
	YoutubeChannels     []string        `json:"youtube_channels,omitempty"`
	PublicDriveFiles    []DriveFile     `json:"public_drive_files,omitempty"`
	RecoveryEmail       string          `json:"recovery_email,omitempty"`
	PhoneLinked         bool            `json:"phone_linked"`
	GoogleID            string          `json:"google_id,omitempty"`
	GoogleIDResults     *GoogleIDResult `json:"google_id_results,omitempty"`
}

// GoogleService represents a Google service linked to the Gmail account
type GoogleService struct {
	Name         string `json:"name"`
	LastActivity string `json:"last_activity,omitempty"`
	URL          string `json:"url,omitempty"`
}

// DriveFile represents a public Google Drive file
type DriveFile struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	AccessLevel  string `json:"access_level"`
	LastModified string `json:"last_modified"`
}

// OnlinePresenceInfo tracks overall online presence
type OnlinePresenceInfo struct {
	Websites         []Website         `json:"websites"`
	ForumMemberships []ForumMembership `json:"forum_memberships"`
	NewsReferences   []NewsReference   `json:"news_references"`
	DataAggregators  []string          `json:"data_aggregators"`
	FirstSeenOnline  string            `json:"first_seen_online"`
	LastSeenOnline   string            `json:"last_seen_online"`
}

// Website represents a website where the email was found
type Website struct {
	URL           string `json:"url"`
	Title         string `json:"title"`
	Context       string `json:"context"`
	DiscoveryDate string `json:"discovery_date"`
}

// ForumMembership represents forum/community membership
type ForumMembership struct {
	Forum      string `json:"forum"`
	Username   string `json:"username"`
	JoinDate   string `json:"join_date"`
	PostCount  int    `json:"post_count"`
	LastActive string `json:"last_active"`
	ProfileURL string `json:"profile_url"`
}

// NewsReference represents mentions in news/articles
type NewsReference struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	PublishDate string `json:"publish_date"`
	Publisher   string `json:"publisher"`
	Context     string `json:"context"`
}

// API keys struct
type APIKeys struct {
	HIBPKey        string `json:"hibp_key"`
	MaxMindKey     string `json:"maxmind_key"`
	ShodanKey      string `json:"shodan_key"`
	HunterIOKey    string `json:"hunterio_key"`
	FullContactKey string `json:"fullcontact_key"`
}

// Configuration for the scanner
var (
	APIConfig = APIKeys{
		HIBPKey:        "your-hibp-api-key", // Replace with env vars in production
		MaxMindKey:     "your-maxmind-key",
		ShodanKey:      "your-shodan-key",
		HunterIOKey:    "your-hunterio-key",
		FullContactKey: "your-fullcontact-key",
	}
	UserAgent          = "MercuriesOST/2.0"
	RequestTimeout     = 15 * time.Second
	ConcurrentRequests = 10
)

// AnalyzeEmail conducts a comprehensive analysis of the provided email address
func AnalyzeEmail(emailAddress string) (*EmailAnalysisResult, error) {
	startTime := time.Now()

	// Create a base result structure
	result := &EmailAnalysisResult{
		Email:           emailAddress,
		SearchTimestamp: time.Now().Format(time.RFC3339),
		Metadata:        make(map[string]interface{}),
		OnlinePresence: OnlinePresenceInfo{
			Websites:         []Website{},
			ForumMemberships: []ForumMembership{},
			NewsReferences:   []NewsReference{},
			DataAggregators:  []string{},
		},
	}

	// Validate email using the validator
	validationResult := emailvalidator.ValidateEmail(emailAddress)
	result.ValidFormat = validationResult.IsValid
	result.Metadata["validation_details"] = validationResult

	if !validationResult.IsValid {
		return result, nil
	}

	// Extract username and domain
	parts := strings.Split(emailAddress, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format after parsing: %s", emailAddress)
	}

	result.Username = parts[0]
	result.Domain = parts[1]

	// Use context with timeout for all network operations
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create semaphore for limiting concurrent operations
	sem := make(chan struct{}, ConcurrentRequests)

	// Create wait group for concurrent operations
	var wg sync.WaitGroup

	// Create a mutex for safely updating the result
	var mu sync.Mutex

	// Analyze email patterns
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		patternAnalysis := analyzeEmailPattern(result.Username, result.Domain)
		mu.Lock()
		result.PatternAnalysis = patternAnalysis
		mu.Unlock()
	}()

	// Check for common email services
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		services := identifyEmailService(result.Domain)
		mu.Lock()
		result.CommonServices = services
		mu.Unlock()
	}()

	// Check for security breaches
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		securityInfo, err := checkEmailSecurity(ctx, emailAddress)
		if err == nil {
			mu.Lock()
			result.SecurityInfo = securityInfo
			mu.Unlock()
		}
	}()

	// Gather domain information
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		domainInfo, err := getDomainInfo(ctx, result.Domain)
		if err == nil {
			mu.Lock()
			result.DomainInfo = domainInfo
			mu.Unlock()
		}
	}()

	// Find connected social profiles
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		profiles, err := findSocialProfiles(ctx, result.Username, emailAddress)
		if err == nil {
			mu.Lock()
			result.SocialProfiles = profiles
			mu.Unlock()
		}
	}()

	// Check online presence
	wg.Add(1)
	go func() {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()

		onlinePresence, err := checkOnlinePresence(ctx, emailAddress, result.Username)
		if err == nil {
			mu.Lock()
			result.OnlinePresence = onlinePresence
			mu.Unlock()
		}
	}()

	// Gmail specific checks
	if strings.ToLower(result.Domain) == "gmail.com" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			gmailInfo, err := getGmailSpecificInfo(ctx, emailAddress, result.Username)
			if err == nil {
				mu.Lock()
				result.GmailSpecific = gmailInfo
				mu.Unlock()
			}
		}()
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Record execution time
	result.Metadata["execution_time_ms"] = time.Since(startTime).Milliseconds()

	return result, nil
}

// analyzeEmailPattern examines the email for common patterns
func analyzeEmailPattern(username, domain string) PatternAnalysis {
	patterns := []string{}
	identityComposition := []string{}
	isBusinessEmail := false

	// More comprehensive username analysis
	usernameLower := strings.ToLower(username)

	// Check for first/last name patterns
	nameParts := strings.Split(username, ".")
	if len(nameParts) > 1 {
		patterns = append(patterns, "Username likely contains full name")
		identityComposition = append(identityComposition, fmt.Sprintf("Possible name parts: %s", strings.Join(nameParts, ", ")))
	}

	// Check for year patterns
	yearPattern := regexp.MustCompile(`(19|20)\d{2}`)
	if year := yearPattern.FindString(username); year != "" {
		patterns = append(patterns, fmt.Sprintf("Username contains year: %s", year))
		birthYear, _ := time.Parse("2006", year)
		currentYear := time.Now().Year()
		potentialAge := currentYear - birthYear.Year()

		if potentialAge >= 15 && potentialAge <= 80 {
			patterns = append(patterns, fmt.Sprintf("Year %s could indicate birth year (potential age: %d)", year, potentialAge))
			identityComposition = append(identityComposition, fmt.Sprintf("Potential birth year: %s (age: ~%d)", year, potentialAge))
		}
	}

	// Check for common words in usernames
	commonWords := map[string]string{
		"admin":     "Administrative account",
		"support":   "Support account",
		"info":      "Information account",
		"sales":     "Sales account",
		"contact":   "Contact account",
		"help":      "Help/assistance account",
		"dev":       "Developer account",
		"webmaster": "Website administrator",
		"marketing": "Marketing account",
		"official":  "Official entity account",
		"service":   "Service account",
		"personal":  "Personally identified account",
		"private":   "Privacy-focused account",
		"noreply":   "Automated non-reply account",
	}

	for word, description := range commonWords {
		if strings.Contains(usernameLower, word) {
			patterns = append(patterns, fmt.Sprintf("Username contains '%s' - possible %s", word, description))
		}
	}

	// Check for sequential numbers
	seqNumbers := regexp.MustCompile(`\d+`)
	if nums := seqNumbers.FindString(username); nums != "" {
		patterns = append(patterns, fmt.Sprintf("Contains numeric sequence: %s", nums))

		// Check if the numbers could be a birth year
		if len(nums) == 4 && strings.HasPrefix(nums, "19") || strings.HasPrefix(nums, "20") {
			year, _ := strconv.Atoi(nums)
			currentYear := time.Now().Year()
			if year >= 1940 && year <= currentYear-15 {
				identityComposition = append(identityComposition, fmt.Sprintf("Numeric sequence %s could indicate birth year (age: ~%d)", nums, currentYear-year))
			}
		} else if len(nums) == 2 {
			shortYear, _ := strconv.Atoi(nums)
			prefix := "19"
			if shortYear < 10 {
				prefix = "200"
			} else if shortYear < 24 { // Adjust based on current year
				prefix = "20"
			}
			fullYear, _ := strconv.Atoi(prefix + nums)
			currentYear := time.Now().Year()
			if fullYear >= 1940 && fullYear <= currentYear-15 {
				identityComposition = append(identityComposition, fmt.Sprintf("Numeric sequence %s could indicate birth year '%s%s' (age: ~%d)", nums, prefix, nums, currentYear-fullYear))
			}
		}
	}

	// Check if business domain
	commonPersonalDomains := []string{
		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
		"aol.com", "icloud.com", "protonmail.com", "mail.com",
		"zoho.com", "yandex.com", "inbox.com", "gmx.com",
		"live.com", "me.com", "mac.com", "msn.com",
		"fastmail.com", "tutanota.com", "mail.ru", "web.de",
	}

	isPersonalDomain := false
	for _, pd := range commonPersonalDomains {
		if strings.EqualFold(domain, pd) {
			isPersonalDomain = true
			patterns = append(patterns, fmt.Sprintf("Uses common personal email provider: %s", pd))
			break
		}
	}

	if !isPersonalDomain {
		isBusinessEmail = true
		patterns = append(patterns, "Domain appears to be a business/organization domain")
	}

	// Check common business email patterns
	if strings.Contains(username, ".") {
		patterns = append(patterns, "Username contains periods (common in business emails)")
	}

	namePattern := regexp.MustCompile(`^[a-zA-Z]+\.[a-zA-Z]+$`)
	if namePattern.MatchString(username) {
		patterns = append(patterns, "Username follows firstname.lastname pattern")
		nameParts := strings.Split(username, ".")
		identityComposition = append(identityComposition, fmt.Sprintf("Likely first name: %s", strings.Title(nameParts[0])))
		identityComposition = append(identityComposition, fmt.Sprintf("Likely last name: %s", strings.Title(nameParts[1])))
	}

	initialLastnamePattern := regexp.MustCompile(`^[a-zA-Z]\.[a-zA-Z]+$`)
	if initialLastnamePattern.MatchString(username) {
		patterns = append(patterns, "Username follows initial.lastname pattern")
		nameParts := strings.Split(username, ".")
		identityComposition = append(identityComposition, fmt.Sprintf("Likely first initial: %s", strings.ToUpper(nameParts[0])))
		identityComposition = append(identityComposition, fmt.Sprintf("Likely last name: %s", strings.Title(nameParts[1])))
	}

	// Advanced pattern detection for Gmail dots trick
	if strings.ToLower(domain) == "gmail.com" {
		if strings.Contains(username, ".") {
			patterns = append(patterns, "Gmail ignores dots in usernames - all emails to username with different dot placements will arrive at this inbox")
		}

		// Check for Gmail plus addressing
		if strings.Contains(username, "+") {
			parts := strings.Split(username, "+")
			baseUsername := parts[0]
			tag := parts[1]
			patterns = append(patterns, fmt.Sprintf("Using Gmail plus addressing with base username '%s' and tag '%s'", baseUsername, tag))
			patterns = append(patterns, "All emails sent to this address will arrive at the base Gmail account")
		}
	}

	// Check for common user patterns
	firstLastPattern := regexp.MustCompile(`^([a-z]+)([a-z]+)(\d*)$`)
	if matches := firstLastPattern.FindStringSubmatch(usernameLower); len(matches) > 2 {
		// This could be firstnamelastname
		first := matches[1]
		last := matches[2]

		// Only add if reasonable name lengths (to avoid false positives)
		if len(first) >= 2 && len(first) <= 12 && len(last) >= 2 && len(last) <= 15 {
			patterns = append(patterns, "Username may follow firstnamelastname pattern")
			identityComposition = append(identityComposition, fmt.Sprintf("Possible first name: %s", strings.Title(first)))
			identityComposition = append(identityComposition, fmt.Sprintf("Possible last name: %s", strings.Title(last)))
		}
	}

	return PatternAnalysis{
		IsBusinessEmail:     isBusinessEmail,
		Patterns:            patterns,
		IdentityComposition: identityComposition,
	}
}

// identifyEmailService identifies the email service provider with detailed information
func identifyEmailService(domain string) []string {
	services := []string{}

	// Map of domains to services with more detail
	domainServices := map[string]string{
		"gmail.com":      "Google Gmail - Free email service with 15GB storage",
		"googlemail.com": "Google Gmail (older domain) - Redirects to gmail.com",
		"yahoo.com":      "Yahoo Mail - Email service with 1TB storage",
		"hotmail.com":    "Microsoft Hotmail (legacy) - Now part of Outlook",
		"outlook.com":    "Microsoft Outlook - Personal email with Office integration",
		"live.com":       "Microsoft Live - Legacy Microsoft email service",
		"aol.com":        "AOL Mail - America Online legacy email service",
		"icloud.com":     "Apple iCloud - Apple's email service with 5GB free storage",
		"me.com":         "Apple iCloud (older domain) - Legacy Apple email",
		"mac.com":        "Apple Mail (older domain) - Original Apple email service",
		"protonmail.com": "ProtonMail - Swiss encrypted email service with privacy focus",
		"protonmail.ch":  "ProtonMail - Swiss domain variant",
		"pm.me":          "ProtonMail - Short domain variant for paid accounts",
		"zoho.com":       "Zoho Mail - Business email service with free tier",
		"yandex.com":     "Yandex Mail - Russian email service with 10GB storage",
		"mail.ru":        "Mail.ru - Popular Russian email service",
		"gmx.com":        "GMX Mail - German email provider with unlimited storage",
		"gmx.net":        "GMX Mail - German domain variant",
		"tutanota.com":   "Tutanota - German encrypted email with privacy focus",
		"fastmail.com":   "FastMail - Premium email service with custom domains",
		"web.de":         "Web.de - German email provider owned by 1&1",
		"t-online.de":    "T-Online - German telecommunications provider email",
		"mailbox.org":    "Mailbox.org - Privacy-focused German email service",
		"hey.com":        "HEY - Premium email service by Basecamp",
		"disroot.org":    "Disroot - Privacy-focused email and cloud services",
	}

	// Check for known services
	if service, exists := domainServices[strings.ToLower(domain)]; exists {
		services = append(services, service)
	} else if strings.HasSuffix(domain, "edu") {
		services = append(services, fmt.Sprintf("Educational Institution Email (%s)", domain))
	} else if strings.HasSuffix(domain, "gov") {
		services = append(services, fmt.Sprintf("Government Email (%s)", domain))
	} else if strings.HasSuffix(domain, "mil") {
		services = append(services, fmt.Sprintf("Military Email (%s)", domain))
	} else {
		// Check if this is a Google Workspace domain
		if isGoogleWorkspaceDomain(domain) {
			services = append(services, fmt.Sprintf("Google Workspace Custom Domain (%s)", domain))
		} else if isMicrosoftDomain(domain) {
			services = append(services, fmt.Sprintf("Microsoft 365 Custom Domain (%s)", domain))
		} else {
			services = append(services, fmt.Sprintf("Custom domain (%s) or specialized email provider", domain))
		}
	}

	return services
}

// isGoogleWorkspaceDomain checks if the domain uses Google Workspace
func isGoogleWorkspaceDomain(domain string) bool {
	// In a real implementation, this would check MX records for Google Workspace patterns
	// For example, looking for mx records ending with googlemail.com
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second * 5}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return false
	}

	for _, mx := range mxRecords {
		if strings.Contains(strings.ToLower(mx.Host), "google") ||
			strings.Contains(strings.ToLower(mx.Host), "googlemail.com") ||
			strings.Contains(strings.ToLower(mx.Host), "aspmx.l.google.com") {
			return true
		}
	}

	return false
}

// isMicrosoftDomain checks if the domain uses Microsoft 365
func isMicrosoftDomain(domain string) bool {
	// Similar to Google Workspace check, but for Microsoft domains
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second * 5}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return false
	}

	for _, mx := range mxRecords {
		if strings.Contains(strings.ToLower(mx.Host), "protection.outlook.com") ||
			strings.Contains(strings.ToLower(mx.Host), "mail.protection.outlook.com") {
			return true
		}
	}

	return false
}

// checkEmailSecurity checks if the email has been part of known data breaches
func checkEmailSecurity(ctx context.Context, email string) (SecurityInfo, error) {
	info := SecurityInfo{
		BreachCount:       0,
		BreachDetails:     []BreachDetail{},
		LeakSources:       []string{},
		ExposedPasswords:  0,
		ExposedDataTypes:  []string{},
		RecentActivityIPs: []string{},
		Metadata:          make(map[string]interface{}),
	}

	// Check for breaches using Have I Been Pwned API
	breaches, err := checkHaveIBeenPwned(ctx, email)
	if err == nil && len(breaches) > 0 {
		info.BreachCount = len(breaches)
		info.LeakSources = append(info.LeakSources, "Have I Been Pwned Database")

		var lastBreachDate time.Time
		dataTypesMap := make(map[string]bool)

		for _, breach := range breaches {
			// Process each breach
			breachDetail := BreachDetail{
				BreachName:      breach.Name,
				BreachDate:      breach.BreachDate,
				CompromisedData: breach.DataClasses,
				Description:     breach.Description,
				IsSensitive:     breach.IsSensitive,
				IsVerified:      breach.IsVerified,
			}

			info.BreachDetails = append(info.BreachDetails, breachDetail)

			// Track the latest breach date
			breachTime, err := time.Parse("2006-01-02", breach.BreachDate)
			if err == nil {
				if lastBreachDate.IsZero() || breachTime.After(lastBreachDate) {
					lastBreachDate = breachTime
				}
			}

			// Track all unique exposed data types
			for _, dataType := range breach.DataClasses {
				dataTypesMap[dataType] = true

				// Count exposed passwords
				if strings.Contains(strings.ToLower(dataType), "password") {
					info.ExposedPasswords++
				}
			}
		}

		// Set the last breach date
		if !lastBreachDate.IsZero() {
			info.LastBreachDate = lastBreachDate.Format("2006-01-02")
		}

		// Convert data types map to slice
		for dataType := range dataTypesMap {
			info.ExposedDataTypes = append(info.ExposedDataTypes, dataType)
		}
	}

	// Check DeHashed (would require API key)
	dehashed, err := checkDeHashed(ctx, email)
	if err == nil && len(dehashed) > 0 {
		info.BreachCount += len(dehashed)
		info.LeakSources = append(info.LeakSources, "DeHashed")
		// Process DeHashed results (similar to HIBP)
	}

	// Calculate security risk score based on findings
	info.RiskScore = calculateSecurityRiskScore(info)

	// Set reputation and first seen data
	info.Metadata["reputation_score"] = calculateReputationScore(email)
	info.Metadata["first_seen"] = estimateFirstSeen(email)

	// For demonstration, add some recent IP addresses
	// In a real implementation, this could come from various leak sources
	info.RecentActivityIPs = []string{"192.168.1.1", "203.0.113.42", "198.51.100.73"}

	return info, nil
}

// Breach represents a data breach from HIBP
type Breach struct {
	Name        string   `json:"Name"`
	BreachDate  string   `json:"BreachDate"`
	Description string   `json:"Description"`
	DataClasses []string `json:"DataClasses"`
	IsVerified  bool     `json:"IsVerified"`
	IsSensitive bool     `json:"IsSensitive"`
}

// checkHaveIBeenPwned checks the HIBP API for breaches
func checkHaveIBeenPwned(ctx context.Context, email string) ([]Breach, error) {
	client := &http.Client{
		Timeout: RequestTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s", url.QueryEscape(email)),
		nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("hibp-api-key", APIConfig.HIBPKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []Breach{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HIBP API returned status code %d", resp.StatusCode)
	}

	var breaches []Breach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, err
	}

	return breaches, nil
}

// checkDeHashed checks the DeHashed API for leaked credentials
func checkDeHashed(ctx context.Context, email string) ([]map[string]interface{}, error) {
	// This is a placeholder for DeHashed API integration
	// Implementation would be similar to HIBP but with different endpoints and response format
	return []map[string]interface{}{}, nil
}

// calculateSecurityRiskScore determines the risk level based on breach data
func calculateSecurityRiskScore(info SecurityInfo) int {
	score := 100 // Start with perfect score

	// Deduct points based on number of breaches
	score -= info.BreachCount * 5

	// Deduct points for exposed passwords
	score -= info.ExposedPasswords * 10

	// Deduct points based on how recent the last breach was
	if info.LastBreachDate != "" {
		lastBreach, err := time.Parse("2006-01-02", info.LastBreachDate)
		if err == nil {
			yearsSinceLastBreach := time.Since(lastBreach).Hours() / (24 * 365)
			if yearsSinceLastBreach < 1 {
				score -= 20
			} else if yearsSinceLastBreach < 3 {
				score -= 10
			} else if yearsSinceLastBreach < 5 {
				score -= 5
			}
		}
	}

	// Deduct points based on sensitive data exposure
	for _, dataType := range info.ExposedDataTypes {
		switch strings.ToLower(dataType) {
		case "password", "passwords":
			score -= 5
		case "credit cards", "financial data":
			score -= 8
		case "social security number", "government id":
			score -= 10
		}
	}

	// Ensure score stays within 0-100 range
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	return score
}

// calculateReputationScore estimates email reputation based on various factors
func calculateReputationScore(email string) float64 {
	// This would integrate with various reputation databases and scoring systems
	// For now, return a placeholder score
	return 85.0
}

// estimateFirstSeen attempts to determine when the email was first observed online
func estimateFirstSeen(email string) string {
	// This would check various databases and archives for first appearance
	// For now, return a placeholder date
	return "2020-01-01"
}

// getDomainInfo gathers detailed information about an email domain
func getDomainInfo(ctx context.Context, domain string) (DomainInfo, error) {
	info := DomainInfo{
		MXRecords:   []MXRecord{},
		DKIMRecords: []string{},
		IPAddresses: []string{},
	}

	// Set up DNS resolver
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Second * 5}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	// Get MX records
	mxs, err := resolver.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxs {
			record := MXRecord{
				Host:     mx.Host,
				Priority: int(mx.Pref),
				Provider: determineMXProvider(mx.Host),
			}
			info.MXRecords = append(info.MXRecords, record)
		}
	}

	// Get SPF record
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err == nil {
		for _, txt := range txtRecords {
			if strings.HasPrefix(txt, "v=spf1") {
				info.SPFRecord = txt
				break
			}
		}
	}

	// Get DMARC record
	dmarcRecords, err := resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err == nil && len(dmarcRecords) > 0 {
		info.DMARCRecord = dmarcRecords[0]
	}

	// Get IP addresses
	ips, err := resolver.LookupIP(ctx, "ip4", domain)
	if err == nil {
		for _, ip := range ips {
			info.IPAddresses = append(info.IPAddresses, ip.String())
		}
	}

	// Calculate DNS health score
	info.DNSHealthScore = calculateDNSHealthScore(info)
	info.EmailQualityScore = calculateEmailQualityScore(info)

	return info, nil
}

// findSocialProfiles searches for linked social media profiles
func findSocialProfiles(ctx context.Context, username, email string) ([]SocialProfile, error) {
	var profiles []SocialProfile
	var wg sync.WaitGroup
	var mu sync.Mutex

	// List of social platforms to check
	platforms := []struct {
		name    string
		checkFn func(context.Context, string) (SocialProfile, error)
	}{
		{"GitHub", checkGitHub},
		{"Twitter", checkTwitter},
		{"LinkedIn", checkLinkedIn},
		{"Facebook", checkFacebook},
		{"Instagram", checkInstagram},
	}

	// Check each platform concurrently
	for _, platform := range platforms {
		wg.Add(1)
		go func(p struct {
			name    string
			checkFn func(context.Context, string) (SocialProfile, error)
		}) {
			defer wg.Done()
			if profile, err := p.checkFn(ctx, username); err == nil {
				mu.Lock()
				profiles = append(profiles, profile)
				mu.Unlock()
			}
		}(platform)
	}

	wg.Wait()
	return profiles, nil
}

// checkOnlinePresence searches for online mentions and activity
func checkOnlinePresence(ctx context.Context, email, username string) (OnlinePresenceInfo, error) {
	presence := OnlinePresenceInfo{
		Websites:         []Website{},
		ForumMemberships: []ForumMembership{},
		NewsReferences:   []NewsReference{},
		DataAggregators:  []string{},
		FirstSeenOnline:  "",
		LastSeenOnline:   "",
	}

	// Search for website mentions
	websites, err := searchWebsiteMentions(ctx, email)
	if err == nil {
		presence.Websites = websites
	}

	// Search for forum memberships
	forums, err := searchForumMemberships(ctx, email, username)
	if err == nil {
		presence.ForumMemberships = forums
	}

	// Search for news references
	news, err := searchNewsReferences(ctx, email)
	if err == nil {
		presence.NewsReferences = news
	}

	// Set first and last seen dates based on findings
	presence.FirstSeenOnline, presence.LastSeenOnline = calculateOnlineDateRange(presence)

	return presence, nil
}

// getGmailSpecificInfo gathers information specific to Gmail accounts
func getGmailSpecificInfo(ctx context.Context, email, username string) (GmailSpecificInfo, error) {
	info := GmailSpecificInfo{
		GoogleServices:    []GoogleService{},
		IsGoogleWorkspace: false,
		PhoneLinked:       false,
	}

	// Extract Google ID if available
	if googleID := extractGoogleID(email); googleID != "" {
		info.GoogleID = googleID

		// Analyze the Google ID
		if results, err := AnalyzeGoogleID(ctx, googleID); err == nil {
			info.GoogleIDResults = results
		}
	}

	// Check Google Workspace status
	if workspace, domain := checkGoogleWorkspace(ctx, email); workspace {
		info.IsGoogleWorkspace = true
		info.WorkspaceDomain = domain
	}

	// Find linked Google services
	services, err := findLinkedGoogleServices(ctx, email)
	if err == nil {
		info.GoogleServices = services
	}

	// Search for public Drive files
	driveFiles, err := searchPublicDriveFiles(ctx, email)
	if err == nil {
		info.PublicDriveFiles = driveFiles
	}

	// Look for YouTube channels
	channels, err := findYouTubeChannels(ctx, email, username)
	if err == nil {
		info.YoutubeChannels = channels
	}

	return info, nil
}

// Add new function to extract Google ID
func extractGoogleID(email string) string {
	// This is a placeholder function
	// In reality, you would need to implement various methods to discover
	// the Google ID associated with an email address
	return ""
}

// Helper functions for domain info
func determineMXProvider(host string) string {
	host = strings.ToLower(host)
	switch {
	case strings.Contains(host, "google"):
		return "Google Workspace"
	case strings.Contains(host, "outlook.com"):
		return "Microsoft 365"
	case strings.Contains(host, "protonmail"):
		return "ProtonMail"
	default:
		return "Unknown"
	}
}

func calculateDNSHealthScore(info DomainInfo) int {
	score := 100
	if info.SPFRecord == "" {
		score -= 20
	}
	if info.DMARCRecord == "" {
		score -= 20
	}
	if len(info.MXRecords) == 0 {
		score -= 30
	}
	return score
}

func calculateEmailQualityScore(info DomainInfo) int {
	score := 100
	if len(info.MXRecords) == 0 {
		score -= 50
	}
	if info.SPFRecord == "" || info.DMARCRecord == "" {
		score -= 25
	}
	return score
}

// Helper functions for social profiles
func checkGitHub(ctx context.Context, username string) (SocialProfile, error) {
	// TODO: Implement actual GitHub profile lookup using ctx and username
	return SocialProfile{Platform: "GitHub", Username: username}, nil
}

func checkTwitter(ctx context.Context, username string) (SocialProfile, error) {
	return SocialProfile{Platform: "Twitter"}, nil
}

func checkLinkedIn(ctx context.Context, username string) (SocialProfile, error) {
	return SocialProfile{Platform: "LinkedIn"}, nil
}

func checkFacebook(ctx context.Context, username string) (SocialProfile, error) {
	return SocialProfile{Platform: "Facebook"}, nil
}

func checkInstagram(ctx context.Context, username string) (SocialProfile, error) {
	return SocialProfile{Platform: "Instagram"}, nil
}

// Helper functions for online presence
func searchWebsiteMentions(ctx context.Context, email string) ([]Website, error) {
	// TODO: Implement actual website search using ctx and email
	return []Website{}, nil
}

func searchForumMemberships(ctx context.Context, email, username string) ([]ForumMembership, error) {
	// TODO: Implement actual forum search using ctx, email and username
	return []ForumMembership{}, nil
}

func searchNewsReferences(ctx context.Context, email string) ([]NewsReference, error) {
	// TODO: Implement actual news search using ctx and email
	return []NewsReference{}, nil
}

func calculateOnlineDateRange(presence OnlinePresenceInfo) (string, string) {
	// Use presence to calculate actual first and last seen dates
	firstSeen := time.Now().AddDate(-2, 0, 0)
	lastSeen := time.Now()

	if len(presence.Websites) > 0 {
		// Calculate based on website discovery dates
		for _, site := range presence.Websites {
			if date, err := time.Parse("2006-01-02", site.DiscoveryDate); err == nil {
				if date.Before(firstSeen) {
					firstSeen = date
				}
				if date.After(lastSeen) {
					lastSeen = date
				}
			}
		}
	}

	return firstSeen.Format("2006-01-02"), lastSeen.Format("2006-01-02")
}

// Helper functions for Gmail specific info
func checkGoogleWorkspace(ctx context.Context, email string) (bool, string) {
	// TODO: Implement actual Google Workspace check using ctx and email
	domain := strings.Split(email, "@")[1]
	return false, domain
}

func findLinkedGoogleServices(ctx context.Context, email string) ([]GoogleService, error) {
	// TODO: Implement actual Google services lookup using ctx and email
	return []GoogleService{}, nil
}

func searchPublicDriveFiles(ctx context.Context, email string) ([]DriveFile, error) {
	// TODO: Implement actual Drive files search using ctx and email
	return []DriveFile{}, nil
}

func findYouTubeChannels(ctx context.Context, email, username string) ([]string, error) {
	// TODO: Implement actual YouTube channel search using ctx, email and username
	return []string{}, nil
}

// DisplayResults formats and displays the email analysis results
func (r *EmailAnalysisResult) DisplayResults() {
	color.Cyan("\n=== EMAIL ANALYSIS RESULTS ===")
	color.Yellow("Email: %s", r.Email)
	color.Yellow("Analysis Timestamp: %s\n", r.SearchTimestamp)

	// Display validation status
	if r.ValidFormat {
		color.Green("✓ Valid email format")
	} else {
		color.Red("✗ Invalid email format")
		return
	}

	// Display basic info
	color.Cyan("\n[Basic Information]")
	color.White("• Username: %s", r.Username)
	color.White("• Domain: %s", r.Domain)

	// Display email service info
	if len(r.CommonServices) > 0 {
		color.Cyan("\n[Email Service]")
		for _, service := range r.CommonServices {
			color.White("• %s", service)
		}
	}

	// Display pattern analysis
	if len(r.PatternAnalysis.Patterns) > 0 {
		color.Cyan("\n[Pattern Analysis]")
		if r.PatternAnalysis.IsBusinessEmail {
			color.White("• Business Email: Yes")
		}
		for _, pattern := range r.PatternAnalysis.Patterns {
			color.White("• %s", pattern)
		}
		if len(r.PatternAnalysis.IdentityComposition) > 0 {
			color.White("\nIdentity Insights:")
			for _, insight := range r.PatternAnalysis.IdentityComposition {
				color.White("  - %s", insight)
			}
		}
	}

	// Display security information
	if r.SecurityInfo.BreachCount > 0 {
		color.Cyan("\n[Security Information]")
		color.Red("• Found in %d data breaches", r.SecurityInfo.BreachCount)
		color.Red("• Exposed passwords: %d", r.SecurityInfo.ExposedPasswords)
		color.White("• Risk Score: %d/100", r.SecurityInfo.RiskScore)
		if r.SecurityInfo.LastBreachDate != "" {
			color.White("• Last breach date: %s", r.SecurityInfo.LastBreachDate)
		}
		if len(r.SecurityInfo.ExposedDataTypes) > 0 {
			color.White("\nExposed Data Types:")
			for _, dataType := range r.SecurityInfo.ExposedDataTypes {
				color.White("  - %s", dataType)
			}
		}
	} else {
		color.Green("\n[Security Information]")
		color.Green("✓ No breaches found")
	}

	// Display domain information
	if len(r.DomainInfo.MXRecords) > 0 {
		color.Cyan("\n[Domain Information]")
		color.White("• DNS Health Score: %d/100", r.DomainInfo.DNSHealthScore)
		color.White("• Email Quality Score: %d/100", r.DomainInfo.EmailQualityScore)
		if r.DomainInfo.SPFRecord != "" {
			color.Green("✓ SPF record found")
		}
		if r.DomainInfo.DMARCRecord != "" {
			color.Green("✓ DMARC record found")
		}
	}

	// Display social profiles
	if len(r.SocialProfiles) > 0 {
		color.Cyan("\n[Connected Social Profiles]")
		for _, profile := range r.SocialProfiles {
			color.White("• %s: %s", profile.Platform, profile.URL)
			if profile.DisplayName != "" {
				color.White("  - Name: %s", profile.DisplayName)
			}
			if profile.LastActive != "" {
				color.White("  - Last active: %s", profile.LastActive)
			}
		}
	}

	// Display online presence
	if len(r.OnlinePresence.Websites) > 0 || len(r.OnlinePresence.ForumMemberships) > 0 {
		color.Cyan("\n[Online Presence]")
		color.White("• First seen online: %s", r.OnlinePresence.FirstSeenOnline)
		color.White("• Last seen online: %s", r.OnlinePresence.LastSeenOnline)

		if len(r.OnlinePresence.Websites) > 0 {
			color.White("\nWebsite Mentions:")
			for _, site := range r.OnlinePresence.Websites {
				color.White("  - %s (%s)", site.Title, site.URL)
			}
		}
	}

	// Display Google ID information if available
	if r.GmailSpecific.GoogleID != "" {
		color.Cyan("\n[Google ID Information]")
		color.White("• Google ID: %s", r.GmailSpecific.GoogleID)

		if r.GmailSpecific.GoogleIDResults != nil {
			r.GmailSpecific.GoogleIDResults.DisplayResults()
		}
	}

	// Display execution time if available
	if execTime, ok := r.Metadata["execution_time_ms"].(int64); ok {
		color.Cyan("\n[Analysis Complete]")
		color.White("Execution time: %dms", execTime)
	}
}
