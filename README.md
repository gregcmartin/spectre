# Spectre - Web Tracking & API Scanner

A powerful Go-based tool designed to detect tracking elements, API specifications, and various web components. It scans websites using parallel processing to efficiently identify tracking pixels, ad networks, API documentation, hidden iframes, and more.

## Features

- Multi-threaded scanning for high performance
- Support for scanning Majestic Million top sites
- Configurable percentage-based scanning
- Comprehensive detection capabilities:
  - API Specifications
    * Swagger/OpenAPI Documentation
    * GraphQL Endpoints and Schemas
    * RAML Documentation
    * API Blueprint
    * Common API Paths
  - Content Management Systems (CMS)
  - Cloud Storage Configurations
  - Tracking Elements
  - Privacy and Compliance Tools
- Detailed statistics and reporting
- JSON output support
- Cross-platform support

For a complete list of detection capabilities, see [PATTERNS.md](PATTERNS.md).

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
  -c        Category to scan (APISpec, TrackingPixel, AdNetwork, AIChat, HiddenIframe, 
            SessionRecording, ErrorTracking, ABTesting, ConsentManagement, 
            Tracking, or 'all')
  -o        Output results to JSON file (e.g., "results.json")
```

### Example Commands

Scan with detailed output:
```bash
./spectre -d example.com
```

Scan for API specifications:
```bash
./spectre -c APISpec example.com
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
  "category": "APISpec",
  "pattern_type": "Swagger UI",
  "value": "swagger-ui.css",
  "location": "example.com#L42",
  "description": "Swagger UI documentation interface for API visualization and testing",
  "risk_level": "Medium",
  "impact": "Exposes API documentation and endpoints which may reveal sensitive implementation details"
}
```

## Project Structure

- `main.go` - Core scanning logic and CLI interface
- `models/types.go` - Data structures and utilities
- `patterns/patterns.go` - Pattern definitions for detection
- `PATTERNS.md` - Detailed documentation of detection capabilities

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
