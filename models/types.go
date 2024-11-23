package models

import (
	"encoding/json"
	"html"
	"os"
	"strings"
	"sync"
)

// Statistics tracks scanning metrics
type Statistics struct {
	ScannedURLs    int64
	ProcessedBytes int64
	FoundSecrets   int64
	Categories     map[string]int
	mu             sync.Mutex
}

// Finding represents a single detected item
type Finding struct {
	Category       string            `json:"category"`
	PatternType    string            `json:"pattern_type"`
	Value          string            `json:"value"`
	Location       string            `json:"location"`
	Description    string            `json:"description"`
	RiskLevel      string            `json:"risk_level"`
	Impact         string            `json:"impact"`
	Implementation map[string]string `json:"implementation,omitempty"`
}

// URLFindings represents all findings for a URL
type URLFindings struct {
	URL      string    `json:"url"`
	Findings []Finding `json:"findings"`
}

// Findings manages all scan findings
type Findings struct {
	Items    []URLFindings
	jsonFile *os.File
	encoder  *json.Encoder
	mu       sync.Mutex
}

// NewStatistics creates a new Statistics instance
func NewStatistics() *Statistics {
	return &Statistics{
		Categories: make(map[string]int),
	}
}

// Increment increases the count for a category
func (s *Statistics) Increment(category string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Categories[category]++
	s.FoundSecrets++
}

// IncrementScanned increases the scanned bytes count
func (s *Statistics) IncrementScanned(bytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ProcessedBytes += bytes
	s.ScannedURLs++
}

// NewFindings creates a new Findings instance
func NewFindings() *Findings {
	return &Findings{
		Items: make([]URLFindings, 0),
	}
}

// InitJSONFile initializes JSON output file
func (f *Findings) InitJSONFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	f.jsonFile = file
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Add pretty printing
	f.encoder = encoder
	return nil
}

// CloseJSONFile closes the JSON output file
func (f *Findings) CloseJSONFile() {
	if f.jsonFile != nil {
		f.jsonFile.Close()
	}
}

// getDescription returns a description based on category and pattern type
func getDescription(category, patternType string) string {
	descriptions := map[string]map[string]string{
		"TrackingPixel": {
			"Facebook Pixel":   "Facebook tracking pixel used for conversion tracking and audience targeting",
			"Google Analytics": "Google Analytics tracking code for website analytics and user behavior tracking",
			"LinkedIn Insight": "LinkedIn Insight Tag for conversion tracking and audience analytics",
			"Twitter Pixel":    "Twitter pixel for conversion tracking and audience targeting",
		},
		"AdNetwork": {
			"Google AdSense": "Google AdSense advertising network integration",
			"Amazon Ads":     "Amazon advertising network integration",
			"Media.net":      "Media.net advertising network integration",
			"Taboola":        "Taboola content recommendation and advertising network",
		},
		"AIChat": {
			"Intercom": "Intercom customer messaging platform",
			"Drift":    "Drift conversational marketing platform",
			"Zendesk":  "Zendesk customer service platform",
			"Crisp":    "Crisp customer messaging platform",
		},
		"HiddenIframe": {
			"Hidden Iframe":    "Hidden iframe potentially used for tracking or third-party content loading",
			"Zero Size Iframe": "Zero-sized iframe potentially used for tracking or third-party content loading",
		},
		"Tracking": {
			"Hotjar":       "Hotjar behavior analytics and user feedback platform",
			"Mouseflow":    "Mouseflow session replay and heatmap tool",
			"FullStory":    "FullStory digital experience analytics platform",
			"Lucky Orange": "Lucky Orange analytics and customer feedback platform",
		},
	}

	if categoryDesc, ok := descriptions[category]; ok {
		if desc, ok := categoryDesc[patternType]; ok {
			return desc
		}
	}
	return "Generic tracking or advertising component"
}

// getRiskLevel returns a risk level based on category
func getRiskLevel(category string) string {
	risks := map[string]string{
		"TrackingPixel": "Medium",
		"AdNetwork":     "Medium",
		"AIChat":        "Low",
		"HiddenIframe":  "High",
		"Tracking":      "Medium",
	}

	if risk, ok := risks[category]; ok {
		return risk
	}
	return "Unknown"
}

// getImpact returns an impact description based on category
func getImpact(category string) string {
	impacts := map[string]string{
		"TrackingPixel": "Enables user behavior tracking and conversion monitoring across sites",
		"AdNetwork":     "Allows targeted advertising and user profiling",
		"AIChat":        "Enables customer interaction monitoring and data collection",
		"HiddenIframe":  "May enable third-party tracking, data collection, or potentially malicious content",
		"Tracking":      "Enables detailed user behavior analysis and session recording",
	}

	if impact, ok := impacts[category]; ok {
		return impact
	}
	return "Potential privacy and security implications"
}

// cleanValue removes HTML entities and normalizes the value
func cleanValue(value string) string {
	// Decode HTML entities
	decoded := html.UnescapeString(value)

	// Remove newlines and extra spaces
	decoded = strings.ReplaceAll(decoded, "\r\n", " ")
	decoded = strings.ReplaceAll(decoded, "\n", " ")

	// Normalize spaces
	decoded = strings.Join(strings.Fields(decoded), " ")

	return decoded
}

// Add adds a new finding
func (f *Findings) Add(url, category, patternType, value, location string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Clean and process the value
	cleanedValue := cleanValue(value)

	// Create implementation details if it's an iframe
	var implementation map[string]string
	if strings.Contains(strings.ToLower(patternType), "iframe") {
		implementation = make(map[string]string)
		if strings.Contains(cleanedValue, "display:none") || strings.Contains(cleanedValue, "visibility:hidden") {
			implementation["visibility"] = "hidden"
		}
		if strings.Contains(cleanedValue, "height=\"0\"") || strings.Contains(cleanedValue, "width=\"0\"") {
			implementation["dimensions"] = "zero-sized"
		}
		if strings.Contains(cleanedValue, "googletagmanager") {
			implementation["type"] = "Google Tag Manager container"
		}
	}

	finding := Finding{
		Category:       category,
		PatternType:    patternType,
		Value:          cleanedValue,
		Location:       location,
		Description:    getDescription(category, patternType),
		RiskLevel:      getRiskLevel(category),
		Impact:         getImpact(category),
		Implementation: implementation,
	}

	// Find existing URL findings or create new
	var urlFindings *URLFindings
	for i := range f.Items {
		if f.Items[i].URL == url {
			urlFindings = &f.Items[i]
			break
		}
	}

	if urlFindings == nil {
		f.Items = append(f.Items, URLFindings{
			URL:      url,
			Findings: []Finding{finding},
		})
	} else {
		urlFindings.Findings = append(urlFindings.Findings, finding)
	}

	// Write to JSON file if enabled
	if f.encoder != nil {
		f.encoder.Encode(finding)
	}
}
