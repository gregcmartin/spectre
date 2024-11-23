package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gregcmartin/spectre/models"
	"github.com/gregcmartin/spectre/patterns"
)

// CompiledPatterns holds pre-compiled regex patterns
type CompiledPatterns struct {
	Category    string
	PatternType string
	Pattern     *regexp.Regexp
}

// Scanner handles the scanning operations
type Scanner struct {
	Stats        *models.Statistics
	Findings     *models.Findings
	Silent       bool
	Detailed     bool
	Majestic     bool
	UserAgent    string
	Category     string
	CompiledPats []CompiledPatterns
}

var (
	thread   *int
	silent   *bool
	ua       *string
	detailed *bool
	majestic *bool
	percent  *int
	category string
	jsonFile *string
)

func init() {
	silent = flag.Bool("s", false, "silent mode")
	thread = flag.Int("t", 50, "number of threads")
	ua = flag.String("ua", "Spectre", "User-Agent")
	detailed = flag.Bool("d", false, "detailed mode")
	majestic = flag.Bool("m", false, "use Majestic Million list")
	percent = flag.Int("p", 100, "percentage of Majestic Million to scan (1-100)")
	jsonFile = flag.String("o", "", "output results to JSON file")
	flag.StringVar(&category, "c", "all", "category to scan (TrackingPixel, AdNetwork, AIChat, HiddenIframe, Tracking, or 'all')")
}

// NewScanner creates a new Scanner instance
func NewScanner(stats *models.Statistics, findings *models.Findings, silent, detailed, majestic bool, ua, category string) *Scanner {
	return &Scanner{
		Stats:        stats,
		Findings:     findings,
		Silent:       silent,
		Detailed:     detailed,
		Majestic:     majestic,
		UserAgent:    ua,
		Category:     category,
		CompiledPats: compilePatterns(category),
	}
}

func banner() {
	fmt.Printf("\033[36m" + `
	███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ███████╗
	██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔════╝
	███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝█████╗  
	╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██╔══╝  
	███████║██║     ███████╗╚██████╗   ██║   ██║  ██║███████╗
	╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝
			` + "\033[36m[\033[37mTracking Scanner\033[36m]\n" +
		`                             ` + "\033[36m[\033[37mVersion 1.0\033[36m]\n")
}

// compilePatterns pre-compiles all regex patterns for better performance
func compilePatterns(category string) []CompiledPatterns {
	var compiled []CompiledPatterns

	for _, pt := range patterns.AllPatternTypes {
		if category != "all" && !strings.EqualFold(category, pt.Category) {
			continue
		}

		re, err := regexp.Compile(pt.Pattern)
		if err != nil {
			continue
		}

		compiled = append(compiled, CompiledPatterns{
			Category:    pt.Category,
			PatternType: pt.Name,
			Pattern:     re,
		})
	}

	return compiled
}

// ProcessMajesticStream processes the Majestic Million list
func (s *Scanner) ProcessMajesticStream(urls chan<- string, percent int) error {
	resp, err := http.Get("https://downloads.majestic.com/majestic_million.csv")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	_, err = reader.Read() // Skip header
	if err != nil {
		return err
	}

	total := 0
	maxDomains := 1000000 // Majestic Million size
	if percent > 0 && percent < 100 {
		maxDomains = (maxDomains * percent) / 100
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			if !s.Silent {
				fmt.Print(drawProgressBar(total, maxDomains))
			}
		}
	}()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if total >= maxDomains {
			break
		}

		if len(record) > 2 {
			urls <- "https://" + record[2]
			total++
		}
	}

	if !s.Silent {
		fmt.Print(drawProgressBar(total, maxDomains))
		fmt.Println()
	}
	return nil
}

// drawProgressBar creates an ASCII progress bar
func drawProgressBar(current, total int) string {
	width := 40
	progress := float64(current) / float64(total)
	filled := int(progress * float64(width))
	percentage := int(progress * 100)

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return fmt.Sprintf("\r\033[34m[*]\033[37m Progress: [%s] %d%% (%d/%d domains)", bar, percentage, current, total)
}

// findMatchLocation finds the line number and context of a match in the content
func findMatchLocation(urlStr, content string, match string) string {
	if match == "" || content == "" {
		return urlStr
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.Contains(line, match) {
			lineNum := i + 1
			return fmt.Sprintf("%s#L%d", urlStr, lineNum)
		}
	}
	return urlStr
}

// getLineNumber returns the line number for a match in the content
func getLineNumber(content, match string) int {
	idx := strings.Index(content, match)
	if idx == -1 {
		return 1
	}
	return strings.Count(content[:idx], "\n") + 1
}

// ScanContent scans content for tracking elements
func (s *Scanner) ScanContent(urlStr string, content string) {
	if content == "" {
		return
	}

	for _, cp := range s.CompiledPats {
		matches := cp.Pattern.FindAllString(content, -1)

		for _, match := range matches {
			cleanedMatch := strings.TrimSpace(match)
			location := findMatchLocation(urlStr, content, match)
			displayLocation := fmt.Sprintf("line %d", getLineNumber(content, match))

			if !s.Silent && !s.Majestic {
				if s.Detailed {
					fmt.Printf("\033[32m[+]\033[37m Found %s (%s) at %s: %s\n", cp.Category, cp.PatternType, displayLocation, cleanedMatch)
				} else {
					fmt.Printf("\033[32m[+]\033[37m Found %s (%s) at %s\n", cp.Category, cp.PatternType, displayLocation)
				}
			}
			s.Stats.Increment(cp.Category)
			s.Findings.Add(urlStr, cp.Category, cp.PatternType, cleanedMatch, location)
		}
	}
}

// ProcessURL processes a single URL
func (s *Scanner) ProcessURL(urlStr string) error {
	if strings.HasPrefix(urlStr, "file://") {
		filePath := strings.TrimPrefix(urlStr, "file://")
		filePath, err := url.QueryUnescape(filePath)
		if err != nil {
			return err
		}

		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			if !s.Silent {
				fmt.Printf("\033[31m[-]\033[37m Error reading file %s: %v\n", filePath, err)
			}
			return err
		}

		s.ScanContent(urlStr, string(content))
		return nil
	}

	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return fmt.Errorf("invalid URL format")
	}

	transp := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transp,
		Timeout:   10 * time.Second,
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", s.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	s.ScanContent(urlStr, string(body))
	return nil
}

func printStats(stats *models.Statistics) {
	if !*majestic {
		fmt.Printf("\n\033[34m[*]\033[37m Scan Statistics:\n")
		fmt.Printf("    URLs Scanned: %d\n", stats.ScannedURLs)
		fmt.Printf("    Elements Found: %d\n", stats.FoundSecrets)
		fmt.Printf("    Data Processed: %.2f MB\n", float64(stats.ProcessedBytes)/1024/1024)

		if len(stats.Categories) > 0 {
			fmt.Printf("\n    Elements by Category:\n")
			for category, count := range stats.Categories {
				fmt.Printf("    - %s: %d\n", category, count)
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	flag.Parse()

	if !*silent && !*majestic {
		banner()
	}

	stats := models.NewStatistics()
	findings := models.NewFindings()

	// Initialize JSON file if output is requested
	outputFile := *jsonFile
	if *majestic && outputFile == "" {
		outputFile = "spectre_results.json"
	}
	if outputFile != "" {
		if err := findings.InitJSONFile(outputFile); err != nil {
			fmt.Printf("\033[31m[-]\033[37m Error initializing JSON file: %v\n", err)
			os.Exit(1)
		}
		defer findings.CloseJSONFile()
	}

	scanner := NewScanner(stats, findings, *silent, *detailed, *majestic, *ua, category)
	urls := make(chan string)

	startTime := time.Now()

	// Start worker goroutines
	done := make(chan bool)
	for i := 0; i < *thread; i++ {
		go func() {
			for url := range urls {
				scanner.ProcessURL(url)
			}
			done <- true
		}()
	}

	// Handle different input modes
	if *majestic {
		// Handle Majestic Million mode
		err := scanner.ProcessMajesticStream(urls, *percent)
		if err != nil {
			fmt.Println("\033[31m[-]\033[37m Error processing Majestic Million list:", err)
			os.Exit(1)
		}
	} else if len(flag.Args()) > 0 {
		// Handle command line arguments
		for _, arg := range flag.Args() {
			// If it's a file path without protocol, add file:// prefix
			if !strings.HasPrefix(arg, "http://") && !strings.HasPrefix(arg, "https://") && !strings.HasPrefix(arg, "file://") {
				absPath, err := filepath.Abs(arg)
				if err == nil {
					arg = "file://" + absPath
				}
			}
			urls <- arg
		}
	} else {
		// Handle stdin mode
		stdinScanner := bufio.NewScanner(os.Stdin)
		for stdinScanner.Scan() {
			urls <- stdinScanner.Text()
		}
	}

	close(urls)

	// Wait for all workers to finish
	for i := 0; i < *thread; i++ {
		<-done
	}

	if !*silent && !*majestic {
		duration := time.Since(startTime)
		fmt.Printf("\n\033[34m[*]\033[37m Scan completed in %.2f seconds\n", duration.Seconds())
		printStats(stats)
	}

	if outputFile != "" && !*silent && !*majestic {
		fmt.Printf("\n\033[34m[*]\033[37m Results written to: %s\n", outputFile)
	}
}
