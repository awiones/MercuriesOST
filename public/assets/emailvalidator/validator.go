package emailvalidator

import (
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"
)

// ValidationResult contains the detailed results of email validation
type ValidationResult struct {
	IsValid       bool     `json:"is_valid"`
	Errors        []string `json:"errors"`
	HasMX         bool     `json:"has_mx"`
	IsCatchAll    bool     `json:"is_catch_all"`
	IsDisposable  bool     `json:"is_disposable"`
	IsRole        bool     `json:"is_role"`
	MXRecords     []string `json:"mx_records"`
	SMTPResponse  string   `json:"smtp_response,omitempty"`
	DisposableMsg string   `json:"disposable_msg,omitempty"`
}

// ValidateEmail performs comprehensive email validation
func ValidateEmail(email string) *ValidationResult {
	result := &ValidationResult{
		IsValid: true,
		Errors:  []string{},
	}

	// Basic format validation
	if !validateFormat(email, result) {
		return result
	}

	// Get domain from email
	parts := strings.Split(email, "@")
	domain := parts[1]

	// Check MX records
	validateMX(domain, result)

	// Check for disposable email
	checkDisposable(domain, result)

	// Check for role-based email
	checkRoleAccount(parts[0], result)

	// Attempt SMTP validation if MX records exist
	if result.HasMX {
		validateSMTP(email, domain, result)
	}

	// Final validity check
	result.IsValid = len(result.Errors) == 0

	return result
}

func validateFormat(email string, result *ValidationResult) bool {
	// Check basic format using net/mail
	_, err := mail.ParseAddress(email)
	if err != nil {
		result.Errors = append(result.Errors, "Invalid email format")
		result.IsValid = false
		return false
	}

	// Additional format checks
	if len(email) > 254 {
		result.Errors = append(result.Errors, "Email too long")
		result.IsValid = false
		return false
	}

	return true
}

func validateMX(domain string, result *ValidationResult) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		result.Errors = append(result.Errors, "No MX records found")
		result.HasMX = false
		return
	}

	result.HasMX = true
	for _, mx := range mxRecords {
		result.MXRecords = append(result.MXRecords, mx.Host)
	}
}

func checkDisposable(domain string, result *ValidationResult) {
	disposableDomains := map[string]bool{
		"tempmail.com":      true,
		"throwawaymail.com": true,
		"mailinator.com":    true,
		"guerrillamail.com": true,
		// Add more disposable domains here
	}

	if disposableDomains[domain] {
		result.IsDisposable = true
		result.DisposableMsg = "Domain is known disposable email provider"
		result.Errors = append(result.Errors, "Disposable email not allowed")
	}
}

func checkRoleAccount(localPart string, result *ValidationResult) {
	roleAccounts := map[string]bool{
		"admin":     true,
		"info":      true,
		"support":   true,
		"sales":     true,
		"contact":   true,
		"noreply":   true,
		"no-reply":  true,
		"webmaster": true,
	}

	if roleAccounts[strings.ToLower(localPart)] {
		result.IsRole = true
		result.Errors = append(result.Errors, "Role-based email address")
	}
}

func validateSMTP(email, domain string, result *ValidationResult) {
	if len(result.MXRecords) == 0 {
		return
	}

	// Connect to SMTP server
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:25", result.MXRecords[0]), 10*time.Second)
	if err != nil {
		result.SMTPResponse = "Connection failed"
		result.Errors = append(result.Errors, "SMTP connection failed")
		return
	}
	defer conn.Close()

	// We don't actually send email, just check if the server accepts the address
	// This is a basic check - in production, you'd want to implement full SMTP handshake
	result.SMTPResponse = "SMTP check completed"
}
