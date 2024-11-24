package patterns

import (
	"regexp"
	"testing"
)

func TestAPISpecPatterns(t *testing.T) {
	tests := []struct {
		patternName string
		content     string
		want        bool
	}{
		{
			patternName: "Swagger UI",
			content:     `<link rel="stylesheet" href="swagger-ui.css">`,
			want:        true,
		},
		{
			patternName: "GraphQL",
			content:     `endpoint: "/graphql"`,
			want:        true,
		},
		{
			patternName: "RAML",
			content:     `api.raml`,
			want:        true,
		},
		{
			patternName: "API Blueprint",
			content:     `FORMAT: 1A\n# My API Blueprint`,
			want:        true,
		},
		{
			patternName: "Common API Paths",
			content:     `/api/v1/users`,
			want:        true,
		},
		{
			patternName: "Swagger UI",
			content:     "regular webpage content",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.patternName, func(t *testing.T) {
			var pattern *PatternType
			for _, p := range apiSpecPatterns {
				if p.Name == tt.patternName {
					pattern = &p
					break
				}
			}
			if pattern == nil {
				t.Fatalf("Pattern not found: %s", tt.patternName)
			}

			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				t.Fatalf("Failed to compile pattern %s: %v", pattern.Name, err)
			}

			got := re.MatchString(tt.content)
			if got != tt.want {
				t.Errorf("Pattern %s: got %v, want %v for content: %s", pattern.Name, got, tt.want, tt.content)
			}
		})
	}
}

func TestTrackingPatterns(t *testing.T) {
	tests := []struct {
		patternName string
		content     string
		want        bool
	}{
		{
			patternName: "Facebook Pixel",
			content:     `fbq('track', 'PageView');`,
			want:        true,
		},
		{
			patternName: "Google Analytics",
			content:     `ga('send', 'pageview');`,
			want:        true,
		},
		{
			patternName: "Facebook Pixel",
			content:     "regular webpage content",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.patternName, func(t *testing.T) {
			var pattern *PatternType
			for _, p := range trackingPixelPatterns {
				if p.Name == tt.patternName {
					pattern = &p
					break
				}
			}
			if pattern == nil {
				t.Fatalf("Pattern not found: %s", tt.patternName)
			}

			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				t.Fatalf("Failed to compile pattern %s: %v", pattern.Name, err)
			}

			got := re.MatchString(tt.content)
			if got != tt.want {
				t.Errorf("Pattern %s: got %v, want %v for content: %s", pattern.Name, got, tt.want, tt.content)
			}
		})
	}
}

func TestHiddenIframePatterns(t *testing.T) {
	tests := []struct {
		patternName string
		content     string
		want        bool
	}{
		{
			patternName: "Hidden Iframe",
			content:     `<iframe style="display:none" src="tracker.html"></iframe>`,
			want:        true,
		},
		{
			patternName: "Zero Size Iframe",
			content:     `<iframe width="0" height="0" src="tracker.html"></iframe>`,
			want:        true,
		},
		{
			patternName: "Dynamic Hidden Iframe",
			content:     `createElement('iframe').style.display = 'none';`,
			want:        true,
		},
		{
			patternName: "Hidden Iframe",
			content:     `<iframe src="video.html"></iframe>`,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.patternName, func(t *testing.T) {
			var pattern *PatternType
			for _, p := range hiddenIframePatterns {
				if p.Name == tt.patternName {
					pattern = &p
					break
				}
			}
			if pattern == nil {
				t.Fatalf("Pattern not found: %s", tt.patternName)
			}

			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				t.Fatalf("Failed to compile pattern %s: %v", pattern.Name, err)
			}

			got := re.MatchString(tt.content)
			if got != tt.want {
				t.Errorf("Pattern %s: got %v, want %v for content: %s", pattern.Name, got, tt.want, tt.content)
			}
		})
	}
}

func TestPatternCompilation(t *testing.T) {
	// Test that all patterns compile successfully
	for _, pattern := range AllPatternTypes {
		_, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			t.Errorf("Failed to compile pattern %s: %v", pattern.Name, err)
		}
	}
}

func TestCategoryUniqueness(t *testing.T) {
	// Test that each pattern type within a category is unique
	seen := make(map[string]bool)
	for _, pattern := range AllPatternTypes {
		key := pattern.Category + ":" + pattern.Name
		if seen[key] {
			t.Errorf("Duplicate pattern found: %s in category %s", pattern.Name, pattern.Category)
		}
		seen[key] = true
	}
}

func TestPatternValidity(t *testing.T) {
	// Test that no pattern is empty
	for _, pattern := range AllPatternTypes {
		if pattern.Pattern == "" {
			t.Errorf("Empty pattern found for %s in category %s", pattern.Name, pattern.Category)
		}
		if pattern.Name == "" {
			t.Errorf("Empty name found in category %s", pattern.Category)
		}
		if pattern.Category == "" {
			t.Errorf("Empty category found for pattern %s", pattern.Name)
		}
	}
}
