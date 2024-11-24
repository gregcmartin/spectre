# Pattern Matching Capabilities

This document details all the pattern matching capabilities of the Spectre scanner.

## API Specifications [APISpec]

- **Swagger/OpenAPI**
  - Swagger UI components and documentation
  - OpenAPI specification files
  - API documentation endpoints

- **GraphQL**
  - GraphQL endpoints and playgrounds
  - Schema definitions
  - Development tools (GraphiQL, Altair)

- **RAML**
  - RAML documentation files
  - API console components
  - JavaScript generators

- **API Blueprint**
  - Blueprint documentation files
  - Apiary.io integration
  - Documentation tools (Aglio, Snowboard, Drakov)

- **Common API Paths**
  - Version-specific API endpoints
  - Documentation directories
  - Schema locations
  - Reference materials

## Content Management Systems [CMS]

- **WordPress**
  - Core components and themes
  - Admin interfaces
  - Plugin systems

- **Drupal**
  - Core modules and themes
  - Configuration patterns
  - Administrative tools

- **Joomla**
  - Component structure
  - Administrative interfaces
  - Module patterns

- **Ghost**
  - Admin interfaces
  - API endpoints
  - Theme components

- **Shopify**
  - Store components
  - Theme elements
  - Payment systems

- **Magento**
  - Frontend components
  - Store functionality
  - Cookie handling

- **Wix**
  - Site components
  - Dashboard elements
  - Feature integrations

- **Squarespace**
  - Site components
  - CDN patterns
  - Configuration elements

## Cloud Storage [CloudStorage]

- **AWS S3**
  - Bucket patterns
  - Configuration strings
  - Environment variables

- **Azure Blob Storage**
  - Storage accounts
  - Connection strings
  - Configuration patterns

- **Google Cloud Storage**
  - Bucket patterns
  - Service accounts
  - Configuration elements

## Tracking Elements

### Tracking Pixels [TrackingPixel]
- Facebook Pixel
- Google Analytics
- LinkedIn Insight
- Twitter Pixel
- Pinterest Tag
- TikTok Pixel

### Ad Networks [AdNetwork]
- Google AdSense
- Amazon Ads
- Media.net
- Taboola
- Outbrain
- Criteo

### AI Chat Windows [AIChat]
- Intercom
- Drift
- Zendesk
- Crisp
- LiveChat
- Tidio

### Hidden iframes [HiddenIframe]
- CSS-hidden iframes
- Zero-sized iframes
- Dynamically created hidden iframes

### Additional Tracking [Tracking]
- Hotjar
- Mouseflow
- FullStory
- Lucky Orange
- Heap Analytics
- Mixpanel

## Privacy and Compliance

### Consent Management [ConsentManagement]
- OneTrust
- CookieBot
- TrustArc

### Session Recording [SessionRecording]
- LogRocket
- Smartlook
- Microsoft Clarity

### Error Tracking [ErrorTracking]
- Sentry
- Rollbar
- BugSnag

### A/B Testing [ABTesting]
- Optimizely
- VWO (Visual Website Optimizer)
- Google Optimize

## Risk Levels

Pattern matches are categorized by risk level:

- **High Risk**
  - Hidden iframes
  - Cloud storage configurations
  - Exposed API endpoints

- **Medium Risk**
  - Tracking pixels
  - Ad networks
  - API specifications
  - Session recording
  - General tracking

- **Low Risk**
  - CMS components
  - AI chat widgets
  - Consent management
  - Error tracking
  - A/B testing tools

## Usage with -c Flag

When using the `-c` flag, you can specify any of the categories shown in brackets above:

```bash
./spectre -c APISpec example.com    # Scan for API specifications
./spectre -c TrackingPixel site.com # Scan for tracking pixels
./spectre -c all example.com        # Scan for all categories
```

Available categories:
- APISpec
- CMS
- CloudStorage
- TrackingPixel
- AdNetwork
- AIChat
- HiddenIframe
- Tracking
- ConsentManagement
- SessionRecording
- ErrorTracking
- ABTesting
