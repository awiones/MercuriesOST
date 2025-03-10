package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awion/MercuriesOST/public/osint"
	"github.com/fatih/color"
)

// Version information
const (
	AppName    = "MercuriesOST"
	AppVersion = "0.1.0"
)

// Command line flags
var (
	versionFlag = flag.Bool("version", false, "Display version information")
	verboseFlag = flag.Bool("verbose", false, "Enable verbose output")
	outputFlag  = flag.String("output", "", "Output file path")
	username    = flag.String("u", "", "Username to search")
	outputDir   = flag.String("o", "results", "Output directory for results")

	// Direct module flags
	socialMediaFlag = flag.String("social-media", "", "Search social media profiles for a username/name")
	domainFlag      = flag.String("domain", "", "Domain intelligence lookup")
	emailFlag       = flag.String("email", "", "Email intelligence lookup")
	ipFlag          = flag.String("ip", "", "IP address intelligence lookup")
	usernameFlag    = flag.String("username", "", "Username intelligence lookup")
)

func main() {
	// Parse command line flags
	flag.Parse()

	// Display banner
	displayBanner()

	// Handle version flag
	if *versionFlag {
		fmt.Printf("%s version %s\n", AppName, AppVersion)
		os.Exit(0)
	}

	// Handle username-based search
	if *username != "" {
		// Create output directory if it doesn't exist
		if _, err := os.Stat(*outputDir); os.IsNotExist(err) {
			os.MkdirAll(*outputDir, 0755)
		}

		// Generate output filename
		outputFile := filepath.Join(*outputDir, fmt.Sprintf("%s_%s.json",
			*username,
			time.Now().Format("20060102_150405")))

		// Run sequential scan
		fmt.Printf("Starting Mercuries scan for username: %s\n", *username)
		results, err := osint.SearchProfilesSequentially(*username, outputFile, *verboseFlag)

		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\nScan complete! Found %d profiles across %d platforms.\n",
			results.ProfilesFound,
			len(results.Profiles))
		return
	}

	// Handle email intelligence
	if *emailFlag != "" {
		fmt.Println("Running Email Intelligence module...")
		runEmailIntelligence(*emailFlag, *outputFlag)
		return
	}

	// Handle legacy module flags
	switch {
	case *socialMediaFlag != "":
		fmt.Println("Running Social Media Intelligence module...")
		runSocialMediaIntelligence(*socialMediaFlag, *outputFlag)
	case *domainFlag != "":
		fmt.Println("Domain intelligence module not implemented yet")
	case *emailFlag != "":
		fmt.Println("Email intelligence module not implemented yet")
	case *ipFlag != "":
		fmt.Println("IP intelligence module not implemented yet")
	case *usernameFlag != "":
		fmt.Println("Username intelligence module not implemented yet")
	default:
		fmt.Println("Error: Please specify either -u flag or a module flag")
		fmt.Println("Example: -u \"username\" or --social-media \"John Doe\"")
		flag.Usage()
		os.Exit(1)
	}
}

// displayBanner prints the application banner
func displayBanner() {
	banner := `
  __  __                          _      
 |  \/  | ___ _ __ ___ _   _ _ __(_) ___  ___
 | |\/| |/ _ \ '__/ __| | | | '__| |/ _ \/ __|
 | |  | |  __/ | | (__| |_| | |  | |  __/\__ \
 |_|  |_|\___|_|  \___|\__,_|_|  |_|\___||___/
                                                      
 Open Source Intelligence Tool - v` + AppVersion + `
 "Knowledge is power, information is liberty"
 MADE WITH LOVE BY github.com/awiones
`
	color.Cyan(banner)
}

// Update function signature to remove unused parameter
func runSocialMediaIntelligence(query, outputPath string) {
	fmt.Printf("Searching social media for: %s\n", query)

	// Update function call to use verbose flag directly
	results, err := osint.SearchProfilesSequentially(query, outputPath, *verboseFlag)
	if err != nil {
		color.Red("Error: %v", err)
		return
	}

	displaySocialResults(results)
	fmt.Println("Social media intelligence gathering completed")
}

// displaySocialResults formats and displays the social media search results
func displaySocialResults(results *osint.SocialMediaResults) {
	color.Green("\n=== SEARCH RESULTS ===")
	color.Yellow("Query: %s", results.Query)
	color.Yellow("Timestamp: %s", results.Timestamp)
	color.Yellow("Total Profiles Found: %d\n", results.ProfilesFound)

	if results.ProfilesFound == 0 {
		color.Red("\nNo profiles found. Searched platforms:")
		for _, platform := range []string{"Twitter", "Instagram", "Facebook", "LinkedIn", "GitHub", "Reddit", "TikTok"} {
			color.Red("  • %s - No profile found", platform)
		}
		return
	}

	// Group profiles by platform for better organization
	platformProfiles := make(map[string][]osint.ProfileResult)
	for _, profile := range results.Profiles {
		platformProfiles[profile.Platform] = append(platformProfiles[profile.Platform], profile)
	}

	// Display results for each platform
	for platform, profiles := range platformProfiles {
		color.Cyan("\n[%s]", platform)
		for _, profile := range profiles {
			color.Green("  Profile URL: %s", profile.URL)

			if profile.FullName != "" {
				color.White("  • Full Name: %s", profile.FullName)
			}

			if profile.Bio != "" {
				color.White("  • Bio: %s", strings.TrimSpace(profile.Bio))
			}

			if profile.FollowerCount > 0 {
				color.White("  • Followers: %d", profile.FollowerCount)
			}

			if profile.Location != "" {
				color.White("  • Location: %s", profile.Location)
			}

			if len(profile.RecentActivity) > 0 {
				color.White("  • Recent Activity:")
				for i, activity := range profile.RecentActivity[:min(3, len(profile.RecentActivity))] {
					color.White("    %d. %s", i+1, activity)
				}
			}

			if len(profile.Insights) > 0 {
				color.White("  • Insights:")
				for _, insight := range profile.Insights {
					color.White("    - %s", insight)
				}
			}

			fmt.Println()
		}
	}

	// Display summary
	color.Green("\n=== PLATFORM SUMMARY ===")
	for _, platform := range []string{"Twitter", "Instagram", "Facebook", "LinkedIn", "GitHub", "Reddit", "TikTok"} {
		if profiles, exists := platformProfiles[platform]; exists {
			color.Green("  ✓ %s: %d profile(s) found", platform, len(profiles))
		} else {
			color.Red("  ✗ %s: No profile found", platform)
		}
	}
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Add this new function for email intelligence
func runEmailIntelligence(email, outputPath string) {
	fmt.Printf("Analyzing email: %s\n", email)

	// Call the email analysis implementation
	results, err := osint.AnalyzeEmail(email)
	if err != nil {
		color.Red("Error: %v", err)
		return
	}

	// Display results
	displayEmailResults(results)

	// Save results if output path is specified
	if outputPath != "" {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			color.Red("Error saving results: %v", err)
			return
		}
		if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
			color.Red("Error writing to file: %v", err)
			return
		}
		color.Green("Results saved to: %s", outputPath)
	}
}

// displayEmailResults formats and displays the email analysis results
func displayEmailResults(results *osint.EmailAnalysisResult) {
	color.Green("\n=== EMAIL ANALYSIS RESULTS ===")
	color.Yellow("Email: %s", results.Email)
	color.Yellow("Timestamp: %s\n", results.Timestamp)

	// Validity
	if results.Valid {
		color.Green("✓ Email format is valid")
	} else {
		color.Red("✗ Invalid email format")
	}

	// Domain Information
	color.Cyan("\n[Domain Information]")
	color.White("Provider: %s", results.DomainInfo.Provider)
	color.White("Reputation: %s", results.DomainInfo.Reputation)
	color.White("Has MX Records: %v", results.DomainInfo.HasMX)
	color.White("Has SPF: %v", results.DomainInfo.HasSPF)
	color.White("Has DMARC: %v", results.DomainInfo.HasDMARC)

	// Format Analysis
	color.Cyan("\n[Format Analysis]")
	color.White("Pattern: %s", results.Format.Pattern)
	color.White("Contains Name: %v", results.Format.ContainsName)
	color.White("Contains Year: %v", results.Format.ContainsYear)
	color.White("Has Special Characters: %v", results.Format.SpecialChars)

	// Security Concerns
	if results.DisposableEmail {
		color.Red("\n[Security Warning]")
		color.Red("⚠ This appears to be a disposable email address")
	}

	// Insights
	color.Cyan("\n[Insights]")
	for _, insight := range results.Insights {
		color.White("• %s", insight)
	}

	fmt.Println()
}
