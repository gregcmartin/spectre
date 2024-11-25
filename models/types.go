package models

import (
	"encoding/json"
	"fmt"
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
	Items         []URLFindings
	jsonFile      *os.File
	encoder       *json.Encoder
	mu            sync.Mutex
	uniqueEntries map[string]bool // Track unique findings
	writtenKeys   map[string]bool // Track findings already written to JSON
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
		Items:         make([]URLFindings, 0),
		uniqueEntries: make(map[string]bool),
		writtenKeys:   make(map[string]bool),
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
		"APISpec": {
			"Swagger UI":       "Swagger/OpenAPI documentation interface for API visualization and testing",
			"GraphQL":          "GraphQL API endpoint or development tools for querying and manipulating data",
			"RAML":             "RESTful API Modeling Language (RAML) documentation and specifications",
			"API Blueprint":    "API Blueprint documentation format for describing web APIs",
			"Common API Paths": "Standard REST API endpoint patterns and documentation locations",
		},
		"CMS": {
			"WordPress":   "WordPress content management system components and functionality",
			"Drupal":      "Drupal content management platform elements and configurations",
			"Joomla":      "Joomla CMS core components and administrative features",
			"Ghost":       "Ghost publishing platform elements and administrative tools",
			"Shopify":     "Shopify e-commerce platform components and functionality",
			"Magento":     "Magento e-commerce system elements and features",
			"Wix":         "Wix website builder platform components and tools",
			"Squarespace": "Squarespace website platform elements and functionality",
		},
		"CloudStorage": {
			"AWS S3 Bucket":        "Amazon Web Services S3 storage bucket configuration and access",
			"Azure Blob Storage":   "Microsoft Azure Blob storage configuration and connection strings",
			"Google Cloud Storage": "Google Cloud Storage bucket configuration and access details",
		},
		"TrackingPixel": {
			"Facebook Pixel":   "Facebook tracking pixel for conversion tracking and audience targeting",
			"Google Analytics": "Google Analytics tracking code for website analytics and user behavior",
			"LinkedIn Insight": "LinkedIn Insight Tag for conversion tracking and audience analytics",
			"Twitter Pixel":    "Twitter pixel for conversion tracking and audience targeting",
			"Pinterest Tag":    "Pinterest conversion tracking and audience targeting pixel",
			"TikTok Pixel":     "TikTok pixel for conversion tracking and audience targeting",
		},
		"AdNetwork": {
			"Google AdSense": "Google AdSense advertising network integration",
			"Amazon Ads":     "Amazon advertising network integration",
			"Media.net":      "Media.net advertising network integration",
			"Taboola":        "Taboola content recommendation and advertising network",
			"Outbrain":       "Outbrain content discovery and advertising platform",
			"Criteo":         "Criteo retargeting and advertising network",
		},
		"AIChat": {
			"Intercom": "Intercom customer messaging and engagement platform",
			"Drift":    "Drift conversational marketing and sales platform",
			"Zendesk":  "Zendesk customer service and engagement platform",
			"Crisp":    "Crisp customer messaging and support platform",
			"LiveChat": "LiveChat customer service and engagement platform",
			"Tidio":    "Tidio live chat and chatbot platform",
		},
		"HiddenIframe": {
			"Hidden Iframe":         "Hidden iframe using CSS display or visibility properties",
			"Zero Size Iframe":      "Zero-sized iframe with width or height set to 0",
			"Dynamic Hidden Iframe": "Dynamically created hidden iframe using JavaScript",
		},
		"Tracking": {
			"Hotjar":         "Hotjar behavior analytics and user feedback platform",
			"Mouseflow":      "Mouseflow session replay and heatmap analytics tool",
			"FullStory":      "FullStory digital experience analytics platform",
			"Lucky Orange":   "Lucky Orange analytics and customer feedback platform",
			"Heap Analytics": "Heap analytics platform for user behavior tracking",
			"Mixpanel":       "Mixpanel product analytics platform",
		},
		"ConsentManagement": {
			"OneTrust":  "OneTrust privacy and consent management platform",
			"CookieBot": "CookieBot GDPR/CCPA consent management solution",
			"TrustArc":  "TrustArc privacy management and compliance platform",
		},
		"SessionRecording": {
			"LogRocket": "LogRocket session replay and error tracking platform",
			"Smartlook": "Smartlook user session recording and analytics",
			"Clarity":   "Microsoft Clarity behavior analytics and heatmap tool",
		},
		"ErrorTracking": {
			"Sentry":  "Sentry error monitoring and crash reporting platform",
			"Rollbar": "Rollbar error tracking and debugging platform",
			"BugSnag": "BugSnag application stability monitoring platform",
		},
		"ABTesting": {
			"Optimizely":      "Optimizely A/B testing and experimentation platform",
			"VWO":             "Visual Website Optimizer A/B testing platform",
			"Google Optimize": "Google Optimize A/B testing and personalization tool",
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
		"APISpec":           "Medium",
		"CMS":               "Low",
		"CloudStorage":      "High",
		"TrackingPixel":     "Medium",
		"AdNetwork":         "Medium",
		"AIChat":            "Low",
		"HiddenIframe":      "High",
		"Tracking":          "Medium",
		"ConsentManagement": "Low",
		"SessionRecording":  "Medium",
		"ErrorTracking":     "Low",
		"ABTesting":         "Low",
	}

	if risk, ok := risks[category]; ok {
		return risk
	}
	return "Unknown"
}

// getImpact returns an impact description based on category
func getImpact(category string) string {
	impacts := map[string]string{
		"APISpec":           "Exposes API documentation and endpoints which may reveal sensitive implementation details",
		"CMS":               "Reveals content management system information that could be used for targeting exploits",
		"CloudStorage":      "Exposes cloud storage configurations that could lead to data access if misconfigured",
		"TrackingPixel":     "Enables user behavior tracking and conversion monitoring across sites",
		"AdNetwork":         "Allows targeted advertising and user profiling",
		"AIChat":            "Enables customer interaction monitoring and data collection",
		"HiddenIframe":      "May enable third-party tracking, data collection, or potentially malicious content",
		"Tracking":          "Enables detailed user behavior analysis and session recording",
		"ConsentManagement": "Manages user privacy preferences and cookie consent",
		"SessionRecording":  "Records and analyzes user interactions and behavior on the site",
		"ErrorTracking":     "Collects application errors and debugging information",
		"ABTesting":         "Enables website experimentation and user experience testing",
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

	// Create a unique key for this finding
	key := fmt.Sprintf("%s:%s:%s:%s", url, category, patternType, cleanedValue)

	// Check if we've already seen this finding
	if f.uniqueEntries[key] {
		return // Skip duplicate findings
	}
	f.uniqueEntries[key] = true

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

	// Write to JSON file if enabled, but only if we haven't written this finding before
	if f.encoder != nil && !f.writtenKeys[key] {
		f.encoder.Encode(finding)
		f.writtenKeys[key] = true
	}
}
