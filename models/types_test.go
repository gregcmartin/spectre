package models

import (
	"os"
	"testing"
)

func TestFindingDeduplication(t *testing.T) {
	// Create a temporary file for testing JSON output
	tmpfile, err := os.CreateTemp("", "test_findings_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	findings := NewFindings()
	err = findings.InitJSONFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer findings.CloseJSONFile()

	// Test case 1: Add same finding multiple times
	url := "https://example.com"
	category := "CMS"
	patternType := "Drupal"
	value := "/sites/default/files/"
	location := "https://example.com#L27"

	// Add the same finding three times
	findings.Add(url, category, patternType, value, location)
	findings.Add(url, category, patternType, value, location)
	findings.Add(url, category, patternType, value, location)

	// Verify in-memory deduplication
	if len(findings.Items) != 1 {
		t.Errorf("Expected 1 URL finding, got %d", len(findings.Items))
	}
	if len(findings.Items[0].Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(findings.Items[0].Findings))
	}

	// Close the file to ensure all data is written
	findings.CloseJSONFile()

	// Read the JSON file and count entries
	content, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Split content by newlines and count valid JSON objects
	lines := 0
	for _, line := range content {
		if line == '{' {
			lines++
		}
	}

	// Verify JSON output deduplication
	if lines != 1 {
		t.Errorf("Expected 1 JSON entry, got %d", lines)
	}

	// Test case 2: Add findings with different values
	findings = NewFindings()
	err = findings.InitJSONFile(tmpfile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Add findings with different values
	findings.Add(url, category, patternType, value, location)
	findings.Add(url, category, patternType, "/different/path/", location)
	findings.Add(url, category, "WordPress", value, location)

	if len(findings.Items) != 1 {
		t.Errorf("Expected 1 URL finding, got %d", len(findings.Items))
	}
	if len(findings.Items[0].Findings) != 3 {
		t.Errorf("Expected 3 findings, got %d", len(findings.Items[0].Findings))
	}

	// Test case 3: Test HTML entity cleaning
	findings = NewFindings()
	findings.Add(url, category, patternType, "test&nbsp;value", location)
	findings.Add(url, category, patternType, "test value", location)

	if len(findings.Items[0].Findings) != 1 {
		t.Errorf("Expected 1 finding after HTML entity cleaning, got %d", len(findings.Items[0].Findings))
	}

	// Test case 4: Test different URLs
	findings = NewFindings()
	findings.Add("https://site1.com", category, patternType, value, location)
	findings.Add("https://site2.com", category, patternType, value, location)

	if len(findings.Items) != 2 {
		t.Errorf("Expected 2 URL findings for different URLs, got %d", len(findings.Items))
	}
}

func TestStatistics(t *testing.T) {
	stats := NewStatistics()

	// Test category increment
	stats.Increment("CMS")
	stats.Increment("CMS")
	stats.Increment("TrackingPixel")

	if stats.Categories["CMS"] != 2 {
		t.Errorf("Expected CMS count of 2, got %d", stats.Categories["CMS"])
	}
	if stats.Categories["TrackingPixel"] != 1 {
		t.Errorf("Expected TrackingPixel count of 1, got %d", stats.Categories["TrackingPixel"])
	}
	if stats.FoundSecrets != 3 {
		t.Errorf("Expected FoundSecrets count of 3, got %d", stats.FoundSecrets)
	}

	// Test scanned bytes increment
	stats.IncrementScanned(1000)
	stats.IncrementScanned(500)

	if stats.ProcessedBytes != 1500 {
		t.Errorf("Expected ProcessedBytes of 1500, got %d", stats.ProcessedBytes)
	}
	if stats.ScannedURLs != 2 {
		t.Errorf("Expected ScannedURLs count of 2, got %d", stats.ScannedURLs)
	}
}
