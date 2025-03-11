package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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
	AppVersion = "0.1.1"
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
	gidFlag         = flag.String("gid", "", "Google ID intelligence lookup")
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

	// Handle Google ID lookup
	if *gidFlag != "" {
		fmt.Printf("Running Google ID Intelligence module for ID: %s\n", *gidFlag)
		runGoogleIDIntelligence(*gidFlag, *outputFlag)
		return
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

func runEmailIntelligence(email, outputPath string) {
	fmt.Printf("Analyzing email: %s\n", email)

	results, err := osint.AnalyzeEmail(email)
	if err != nil {
		color.Red("Error analyzing email: %v", err)
		return
	}

	// Display results using the new method
	results.DisplayResults()

	// Save to file if output path is specified
	if outputPath != "" {
		if data, err := json.MarshalIndent(results, "", "  "); err == nil {
			if err := os.WriteFile(outputPath, data, 0644); err == nil {
				color.Green("\nResults saved to: %s", outputPath)
			} else {
				color.Red("Error saving results: %v", err)
			}
		} else {
			color.Red("Error encoding results: %v", err)
		}
	}
}

// Add new function to handle Google ID intelligence
func runGoogleIDIntelligence(gid string, outputPath string) {
	fmt.Printf("Analyzing Google ID: %s\n", gid)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Run the Google ID analysis
	results, err := osint.AnalyzeGoogleID(ctx, gid)
	if err != nil {
		color.Red("Error analyzing Google ID: %v", err)
		return
	}

	// Display results
	results.DisplayResults()

	// Save to file if output path is specified
	if outputPath != "" {
		if data, err := json.MarshalIndent(results, "", "  "); err == nil {
			if err := os.WriteFile(outputPath, data, 0644); err == nil {
				color.Green("\nResults saved to: %s", outputPath)
			} else {
				color.Red("Error saving results: %v", err)
			}
		} else {
			color.Red("Error encoding results: %v", err)
		}
	}
}
