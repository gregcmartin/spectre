# Spectre - Web Tracking & Ad Network Scanner

A powerful Go-based tool designed to detect tracking pixels, ad networks, AI chat widgets, hidden iframes, and other tracking elements in web applications. It scans websites using parallel processing to efficiently identify various tracking and advertising components.

## Features

- Multi-threaded scanning for high performance
- Support for scanning Majestic Million top sites
- Configurable percentage-based scanning
- Comprehensive tracking detection:
  - Tracking Pixels (Facebook, Google Analytics, LinkedIn, Twitter, Pinterest, TikTok)
  - Ad Networks (Google AdSense, Amazon Ads, Media.net, Taboola, Outbrain, Criteo)
  - AI Chat Windows (Intercom, Drift, Zendesk, Crisp, LiveChat, Tidio)
  - Hidden iframes (display:none, zero-sized, dynamically created)
  - Session Recording (LogRocket, Smartlook, Clarity)
  - Error Tracking (Sentry, Rollbar, BugSnag)
  - A/B Testing (Optimizely, VWO, Google Optimize)
  - Consent Management (OneTrust, CookieBot, TrustArc)
  - General Tracking (Hotjar, Mouseflow, FullStory, Lucky Orange, Heap Analytics, Mixpanel)
- Detailed statistics and reporting
- JSON output support
- Cross-platform support

## Installation

```bash
# Clone the repository
git clone https://github.com/gregcmartin/spectre.git

# Change into the directory
cd spectre

# Build the project
go build
```

## Usage

### Basic Usage

Scan URLs from stdin:
```bash
cat urls.txt | ./spectre
```

Scan a specific URL:
```bash
echo "https://example.com" | ./spectre
```

Scan a local file:
```bash
./spectre test.html
```

### Advanced Options

```bash
Usage: spectre [options]

Options:
  -s        Silent mode (suppresses banner)
  -t int    Number of threads (default: 50)
  -ua       User-Agent string (default: "Spectre")
  -d        Detailed mode (shows line numbers and matched content)
  -m        Use Majestic Million list for scanning
  -p int    Percentage of Majestic Million to scan (1-100, default: 100)
  -c        Category to scan (TrackingPixel, AdNetwork, AIChat, HiddenIframe, 
            SessionRecording, ErrorTracking, ABTesting, ConsentManagement, 
            Tracking, or 'all')
  -o        Output results to JSON file (e.g., "results.json")
```

### Example Commands

Scan with detailed output:
```bash
./spectre -d example.com
```

Scan specific category:
```bash
./spectre -c TrackingPixel example.com
```

Scan with JSON output:
```bash
./spectre -d -o results.json example.com
```

Scan Majestic Million top 10%:
```bash
./spectre -m -p 10
```

## Output Format

When using JSON output (-o flag), findings are structured as:

```json
{
  "category": "TrackingPixel",
  "pattern_type": "Google Analytics",
  "value": "google-analytics.com/analytics.js",
  "location": "example.com#L42",
  "description": "Google Analytics tracking code for website analytics",
  "risk_level": "Medium",
  "impact": "Enables user behavior tracking and conversion monitoring"
}
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to all contributors who have helped improve the pattern detection
- Inspired by the need for transparent web tracking detection
