package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
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

	// Handle legacy module flags
	switch {
	case *socialMediaFlag != "":
		fmt.Println("Running Social Media Intelligence module...")
		runSocialMediaIntelligence(*socialMediaFlag, *outputFlag, *verboseFlag)
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

// runSocialMediaIntelligence calls the actual implementation and displays results
func runSocialMediaIntelligence(query, outputPath string, verbose bool) {
	fmt.Printf("Searching social media for: %s\n", query)

	// Call the actual implementation
	results, err := osint.SearchProfilesSequentially(query, outputPath, verbose)
	if err != nil {
		color.Red("Error: %v", err)
		return
	}

	// Display results in console regardless of output file
	displaySocialResults(results)

	fmt.Println("Social media intelligence gathering completed")
}

// displaySocialResults formats and displays the social media search results
func displaySocialResults(results *osint.SocialMediaResults) {
	color.Green("\n=== SEARCH RESULTS ===")
	color.Yellow("Query: %s", results.Query)
	color.Yellow("Timestamp: %s", results.Timestamp)
	color.Yellow("Profiles Found: %d\n", results.ProfilesFound)

	if results.ProfilesFound == 0 {
		color.Red("No profiles found for this query.")
		return
	}

	// Display each found profile
	for _, profile := range results.Profiles {
		if profile.Exists {
			// Display profile header
			color.Cyan("\n[+] %s Profile", profile.Platform)
			color.White("    URL: %s", profile.URL)

			// Display detailed information if available
			if profile.FullName != "" {
				color.White("    Full Name: %s", profile.FullName)
			}

			if profile.Bio != "" {
				color.White("    Bio: %s", profile.Bio)
			}

			if profile.FollowerCount > 0 {
				color.White("    Followers: %d", profile.FollowerCount)
			}

			if profile.JoinDate != "" {
				color.White("    Joined: %s", profile.JoinDate)
			}

			if profile.Location != "" {
				color.White("    Location: %s", profile.Location)
			}

			if len(profile.Connections) > 0 {
				color.White("    Notable Connections: %d found", len(profile.Connections))
				// Show up to 3 connections as preview
				connLimit := 3
				if len(profile.Connections) < connLimit {
					connLimit = len(profile.Connections)
				}
				for i := 0; i < connLimit; i++ {
					color.White("      - %s", profile.Connections[i])
				}
			}

			if len(profile.RecentActivity) > 0 {
				color.White("    Recent Activity: %d items found", len(profile.RecentActivity))
				// Show up to 3 activities as preview
				actLimit := 3
				if len(profile.RecentActivity) < actLimit {
					actLimit = len(profile.RecentActivity)
				}
				for i := 0; i < actLimit; i++ {
					color.White("      - %s", profile.RecentActivity[i])
				}
			}

			// Display additional insights if available
			if len(profile.Insights) > 0 {
				color.White("    Insights:")
				for _, insight := range profile.Insights {
					color.White("      - %s", insight)
				}
			}
		}
	}

	// Provide a summary at the end
	fmt.Println()
	color.Green("=== SUMMARY ===")

	// Platform breakdown
	color.White("Platform Breakdown:")
	for _, platform := range []string{"Twitter", "Instagram", "Facebook", "LinkedIn", "GitHub", "Reddit", "TikTok"} {
		found := false
		for _, profile := range results.Profiles {
			if profile.Platform == platform && profile.Exists {
				found = true
				break
			}
		}

		if found {
			color.Green("  [✓] %s", platform)
		} else {
			color.Red("  [✗] %s", platform)
		}
	}

	fmt.Println()
}
