package variations

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// VariationResult represents the JSON structure for variations
type VariationResult struct {
	OriginalName string   `json:"original_name"`
	Timestamp    string   `json:"timestamp"`
	Count        int      `json:"variation_count"`
	Variations   []string `json:"variations"`
}

// GetNameVariations returns common username variations of a given name and saves them to JSON
func GetNameVariations(fullName string) []string {
	variations := make(map[string]bool)

	// Clean input and split into parts
	fullName = strings.TrimSpace(fullName)
	parts := strings.Fields(fullName)
	if len(parts) == 0 {
		return nil
	}

	// Convert to lowercase for username-style variations
	lowerParts := make([]string, len(parts))
	for i, part := range parts {
		lowerParts[i] = strings.ToLower(part)
	}

	// Add original name
	variations[fullName] = true

	// First name, last name (if available)
	firstName := parts[0]
	lastName := ""
	if len(parts) > 1 {
		lastName = parts[len(parts)-1]
	}

	lowerFirst := strings.ToLower(firstName)
	variations[lowerFirst] = true

	// Handle common single-name variations
	if len(firstName) >= 3 {
		// Common truncations (first 3-5 chars)
		for i := 3; i <= 5 && i <= len(firstName); i++ {
			variations[strings.ToLower(firstName[:i])] = true
		}
	}

	// If we have both first and last name
	if lastName != "" {
		lowerLast := strings.ToLower(lastName)
		variations[lowerLast] = true

		// Most common username patterns
		commonPatterns := []string{
			lowerFirst + lowerLast,
			lowerFirst + "." + lowerLast,
			lowerFirst + "_" + lowerLast,
			lowerLast + lowerFirst,
			lowerLast + "." + lowerFirst,
			lowerLast + "_" + lowerFirst,
			lowerFirst[0:1] + lowerLast,
			lowerFirst + lowerLast[0:1],
			lowerFirst[0:1] + "." + lowerLast,
			lowerFirst[0:1] + "_" + lowerLast,
		}

		// Add initial patterns if names are long enough
		if len(lowerFirst) >= 2 && len(lowerLast) >= 2 {
			commonPatterns = append(commonPatterns,
				lowerFirst[0:2]+lowerLast,
				lowerFirst[0:2]+"."+lowerLast,
				lowerFirst[0:2]+"_"+lowerLast,
				lowerFirst+lowerLast[0:2],
				lowerFirst+"."+lowerLast[0:2],
				lowerFirst+"_"+lowerLast[0:2],
			)
		}

		// Add all common patterns
		for _, pattern := range commonPatterns {
			variations[pattern] = true
		}

		// Common number combinations for most popular patterns
		commonNumberPatterns := []string{
			lowerFirst + lowerLast,
			lowerFirst[0:1] + lowerLast,
			lowerLast + lowerFirst,
		}

		// Only add year-style numbers (common for usernames)
		years := []string{"", "1", "123", "321"}
		currentYear := time.Now().Year()
		for y := currentYear - 30; y <= currentYear; y++ {
			years = append(years, fmt.Sprintf("%d", y))
			years = append(years, fmt.Sprintf("%d", y%100)) // Last two digits
		}

		// Add common numbers to patterns
		for _, pattern := range commonNumberPatterns {
			for _, num := range years {
				if num != "" {
					variations[pattern+num] = true
				}
			}
		}

		// Common letter substitutions for l33t speak
		if strings.ContainsAny(lowerFirst+lowerLast, "aeiostu") {
			l33tMap := map[string]string{
				"a": "@",
				"e": "3",
				"i": "1",
				"o": "0",
				"s": "5",
				"t": "7",
				"u": "v",
			}

			// Apply l33t substitutions to the most common pattern
			basePattern := lowerFirst + lowerLast
			for old, new := range l33tMap {
				if strings.Contains(basePattern, old) {
					variations[strings.ReplaceAll(basePattern, old, new)] = true
				}
			}
		}
	} else {
		// Single name variations with numbers
		years := []string{"123", "321"}
		currentYear := time.Now().Year()
		for y := currentYear - 20; y <= currentYear; y++ {
			years = append(years, fmt.Sprintf("%d", y%100))
		}

		for _, num := range years {
			variations[lowerFirst+num] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(variations))
	for v := range variations {
		result = append(result, v)
	}

	// Save variations to JSON file
	SaveVariationsToJSON(fullName, result)

	return result
}

// SaveVariationsToJSON saves name variations to a JSON file in the dump directory
func SaveVariationsToJSON(originalName string, variations []string) error {
	// Create dump directory if it doesn't exist
	dumpDir := "dump"
	if err := os.MkdirAll(dumpDir, 0755); err != nil {
		return err
	}

	// Create variation result
	result := VariationResult{
		OriginalName: originalName,
		Timestamp:    time.Now().Format(time.RFC3339),
		Count:        len(variations),
		Variations:   variations,
	}

	// Create filename from original name
	safeName := strings.ToLower(strings.ReplaceAll(originalName, " ", "-"))
	filename := filepath.Join(dumpDir, fmt.Sprintf("%s-variations.json", safeName))

	// Convert to JSON
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(filename, jsonData, 0644)
}
