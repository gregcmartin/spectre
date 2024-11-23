package patterns

// PatternType defines a pattern to search for
type PatternType struct {
	Category string
	Name     string
	Pattern  string
}

// AllPatternTypes contains all patterns to search for
var AllPatternTypes = []PatternType{
	// CMS Detection
	{
		Category: "CMS",
		Name:     "WordPress",
		Pattern:  `(?i)wp-content|wp-includes|wp-admin|wp-config\.php|wordpress\.com|wordpress\.org|wp_|wordpress_|/wp-json/|wp\.customize|wp\.blocks`,
	},
	{
		Category: "CMS",
		Name:     "Drupal",
		Pattern:  `(?i)drupal\.org|drupal\.settings|drupal\.behaviors|/sites/default/files/|/node/\d+|/admin/content|/sites/all/themes/|/sites/all/modules/`,
	},
	{
		Category: "CMS",
		Name:     "Joomla",
		Pattern:  `(?i)com_content|com_users|com_admin|joomla!|/administrator/|mosConfig_|joomla\.org|joomla\.javascript|/components/com_|/modules/mod_`,
	},
	{
		Category: "CMS",
		Name:     "Ghost",
		Pattern:  `(?i)ghost\.io|ghost-admin|ghost\.|ghost_root_url|ghost\-admin|ghost\.settings|/ghost/api/|@tryghost/`,
	},
	{
		Category: "CMS",
		Name:     "Shopify",
		Pattern:  `(?i)shopify\.com|myshopify\.com|shopify\.section|shopify\.theme|shopify\.assets|\.myshopify\.|shopify\.payment|shopify-buy`,
	},
	{
		Category: "CMS",
		Name:     "Magento",
		Pattern:  `(?i)magento|mage\.|/skin/frontend/|/app/design/frontend/|var magento|mage/cookies\.js|Mage\.Cookies|/checkout/cart/`,
	},
	{
		Category: "CMS",
		Name:     "Wix",
		Pattern:  `(?i)wix\.com|wixsite\.com|wix-code|wix-api|wix-dashboard|wix-locations|wix-events|wix-stores|wix-bookings`,
	},
	{
		Category: "CMS",
		Name:     "Squarespace",
		Pattern:  `(?i)squarespace\.com|sqsp\.com|squarespace-cdn\.com|squarespace\.config|squarespace\.bootstrap|static\.squarespace|static1\.squarespace`,
	},

	// Cloud Storage
	{
		Category: "CloudStorage",
		Name:     "AWS S3 Bucket",
		Pattern:  `(?i)(?:https?://)?(?:[a-zA-Z0-9-]+\.)?s3[.-](?:[a-zA-Z0-9-]+\.)?amazonaws\.com|(?:https?://)?s3://[a-zA-Z0-9-]+|"bucket":\s*"[a-zA-Z0-9-]+"|AWS_BUCKET|S3_BUCKET`,
	},
	{
		Category: "CloudStorage",
		Name:     "Azure Blob Storage",
		Pattern:  `(?i)(?:https?://)?[a-zA-Z0-9-]+\.blob\.core\.windows\.net|DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+|AZURE_STORAGE_CONNECTION_STRING|AZURE_STORAGE_ACCOUNT`,
	},
	{
		Category: "CloudStorage",
		Name:     "Google Cloud Storage",
		Pattern:  `(?i)(?:https?://)?storage\.cloud\.google\.com/[a-zA-Z0-9-]+|(?:https?://)?storage\.googleapis\.com/[a-zA-Z0-9-]+|"type":\s*"service_account"|GOOGLE_CLOUD_BUCKET|GCS_BUCKET`,
	},

	// Tracking Pixels
	{
		Category: "TrackingPixel",
		Name:     "Facebook Pixel",
		Pattern:  `(?i)facebook\.com/tr|facebook\.net/signals|connect\.facebook\.net|fbevents\.js|_fbq\.push`,
	},
	{
		Category: "TrackingPixel",
		Name:     "Google Analytics",
		Pattern:  `(?i)google-analytics\.com|analytics\.js|gtag|ga\.js|googletagmanager\.com|google_analytics|_ga\.push`,
	},
	{
		Category: "TrackingPixel",
		Name:     "LinkedIn Insight",
		Pattern:  `(?i)linkedin\.com/li\.lms-analytics|linkedin\.com/insight|snap\.licdn\.com|_linkedin_data|_linkedin_partner_id`,
	},
	{
		Category: "TrackingPixel",
		Name:     "Twitter Pixel",
		Pattern:  `(?i)static\.ads-twitter\.com|ads-twitter\.com/uwt\.js|twq\(|twitter\.com/i/adsct`,
	},
	{
		Category: "TrackingPixel",
		Name:     "Pinterest Tag",
		Pattern:  `(?i)pintrk\.js|pinimg\.com/ct|pinterest-analytics|pinterest\.com/ct\.html`,
	},
	{
		Category: "TrackingPixel",
		Name:     "TikTok Pixel",
		Pattern:  `(?i)analytics\.tiktok\.com|tiktok\.com/i/pixel|ttq\.track|_tiktok\.push`,
	},

	// Ad Networks
	{
		Category: "AdNetwork",
		Name:     "Google AdSense",
		Pattern:  `(?i)pagead2\.googlesyndication\.com|adsbygoogle|google_ad_client|googleads|adsense\.js`,
	},
	{
		Category: "AdNetwork",
		Name:     "Amazon Ads",
		Pattern:  `(?i)amazon-adsystem\.com|amzn_ads|amzn\.to/ads|amazon-ads-api`,
	},
	{
		Category: "AdNetwork",
		Name:     "Media.net",
		Pattern:  `(?i)media\.net/dmedianet|medianet\.js|media\.net/rtb`,
	},
	{
		Category: "AdNetwork",
		Name:     "Taboola",
		Pattern:  `(?i)cdn\.taboola\.com|taboola\.com/libtrc|_taboola\.push|tbl\.loadRecsetScript`,
	},
	{
		Category: "AdNetwork",
		Name:     "Outbrain",
		Pattern:  `(?i)outbrain\.com/widget|obcdn\.com|ob_click|OBR\.extern\.researchWidget`,
	},
	{
		Category: "AdNetwork",
		Name:     "Criteo",
		Pattern:  `(?i)static\.criteo\.net|criteo\.com/js|criteo_q\.push|crto\.com`,
	},

	// AI Chat Windows
	{
		Category: "AIChat",
		Name:     "Intercom",
		Pattern:  `(?i)intercomcdn\.com|intercom\.io|widget\.intercom\.io|window\.intercomSettings|Intercom\('boot'`,
	},
	{
		Category: "AIChat",
		Name:     "Drift",
		Pattern:  `(?i)drift\.com/embed|js\.driftt\.com|drift\.load|driftt\.com`,
	},
	{
		Category: "AIChat",
		Name:     "Zendesk",
		Pattern:  `(?i)static\.zdassets\.com|zopim\.com|zendesk\.com/embeddable|zEmbed`,
	},
	{
		Category: "AIChat",
		Name:     "Crisp",
		Pattern:  `(?i)crisp\.chat|client\.crisp\.chat|window\.CRISP_WEBSITE_ID|$crisp\.push`,
	},
	{
		Category: "AIChat",
		Name:     "LiveChat",
		Pattern:  `(?i)cdn\.livechatinc\.com|livechatinc\.com/tracking|window\.__lc`,
	},
	{
		Category: "AIChat",
		Name:     "Tidio",
		Pattern:  `(?i)code\.tidio\.co|tidio\.com/|tidioChatCode`,
	},

	// Hidden iframes
	{
		Category: "HiddenIframe",
		Name:     "Hidden Iframe",
		Pattern:  `(?i)<iframe[^>]*(?:style=["'][^"']*(?:display:\s*none|visibility:\s*hidden|opacity:\s*0)[^"']*["'])[^>]*>`,
	},
	{
		Category: "HiddenIframe",
		Name:     "Zero Size Iframe",
		Pattern:  `(?i)<iframe[^>]*(?:width=["']0["']|height=["']0["']|width=["']1["']|height=["']1["'])[^>]*>`,
	},
	{
		Category: "HiddenIframe",
		Name:     "Dynamic Hidden Iframe",
		Pattern:  `(?i)createElement\(['"']iframe['"']\)[^>]*(?:style\.display\s*=\s*['"']none['"']|style\.visibility\s*=\s*['"']hidden['"']|style\.opacity\s*=\s*['"']0['"'])`,
	},

	// Additional Tracking
	{
		Category: "Tracking",
		Name:     "Hotjar",
		Pattern:  `(?i)static\.hotjar\.com|hotjar-|hj\.|hotjar\.com|window\.hjSiteSettings|_hjSettings`,
	},
	{
		Category: "Tracking",
		Name:     "Mouseflow",
		Pattern:  `(?i)mouseflow\.com/projects|_mfq\.push|mouseflow\.init|mouseflowId`,
	},
	{
		Category: "Tracking",
		Name:     "FullStory",
		Pattern:  `(?i)fullstory\.com/s/fs\.js|window\['_fs_host'\]|FS\.identify|_fs_loaded`,
	},
	{
		Category: "Tracking",
		Name:     "Lucky Orange",
		Pattern:  `(?i)luckyorange\.com|window\.__lo_site_id|_loq\.push`,
	},
	{
		Category: "Tracking",
		Name:     "Heap Analytics",
		Pattern:  `(?i)heapanalytics\.com|heap\.load|window\.heap|heap\.track`,
	},
	{
		Category: "Tracking",
		Name:     "Mixpanel",
		Pattern:  `(?i)cdn\.mxpnl\.com|mixpanel\.init|mixpanel\.track`,
	},

	// Consent Management
	{
		Category: "ConsentManagement",
		Name:     "OneTrust",
		Pattern:  `(?i)cdn\.cookielaw\.org|optanon\.blob\.core|OneTrust|otSDKStub`,
	},
	{
		Category: "ConsentManagement",
		Name:     "CookieBot",
		Pattern:  `(?i)consent\.cookiebot\.com|Cookiebot\.renew|window\.Cookiebot`,
	},
	{
		Category: "ConsentManagement",
		Name:     "TrustArc",
		Pattern:  `(?i)consent\.truste\.com|truste\.com/notice|truste-svc\.net`,
	},

	// Session Recording
	{
		Category: "SessionRecording",
		Name:     "LogRocket",
		Pattern:  `(?i)cdn\.logrocket\.com|LogRocket\.init|window\.LogRocket`,
	},
	{
		Category: "SessionRecording",
		Name:     "Smartlook",
		Pattern:  `(?i)smartlook\.com/recorder\.js|window\.smartlook|smartlook\.init`,
	},
	{
		Category: "SessionRecording",
		Name:     "Clarity",
		Pattern:  `(?i)clarity\.ms/tag|microsoft\.com/clarity|clarity\.identify`,
	},

	// Error Tracking
	{
		Category: "ErrorTracking",
		Name:     "Sentry",
		Pattern:  `(?i)browser\.sentry-cdn\.com|Sentry\.init|window\.SENTRY_CONFIG`,
	},
	{
		Category: "ErrorTracking",
		Name:     "Rollbar",
		Pattern:  `(?i)cdn\.rollbar\.com|rollbar\.init|window\._rollbarConfig`,
	},
	{
		Category: "ErrorTracking",
		Name:     "BugSnag",
		Pattern:  `(?i)d2wy8f7a9ursnm\.cloudfront\.net/bugsnag|bugsnag\.init|window\.bugsnag`,
	},

	// A/B Testing
	{
		Category: "ABTesting",
		Name:     "Optimizely",
		Pattern:  `(?i)cdn\.optimizely\.com|optimizely\.init|window\.optimizely`,
	},
	{
		Category: "ABTesting",
		Name:     "VWO",
		Pattern:  `(?i)dev\.visualwebsiteoptimizer\.com|window\._vwo_code|_vwo_api\.js`,
	},
	{
		Category: "ABTesting",
		Name:     "Google Optimize",
		Pattern:  `(?i)optimize\.google\.com|gtag\('config', 'OPT-|google_optimize`,
	},
}
