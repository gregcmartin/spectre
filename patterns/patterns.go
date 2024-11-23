package patterns

// PatternType defines a pattern to search for
type PatternType struct {
	Category string
	Name     string
	Pattern  string
}

// AllPatternTypes contains all patterns to search for
var AllPatternTypes = []PatternType{
	// Legacy Web Technologies - Server Side
	{
		Category: "LegacyTech",
		Name:     "Classic ASP",
		Pattern:  `(?i)<%[@=#]?.*?%>|Response\.Write|Server\.CreateObject|ADODB\.Connection|\.asp\b|VBScript|JScript`,
	},
	{
		Category: "LegacyTech",
		Name:     "PHP Legacy",
		Pattern:  `(?i)<\?(?!xml).*?\?>|mysql_(?:connect|query|select_db)|ereg(?:_replace)?|split\(|session_register|magic_quotes|register_globals`,
	},
	{
		Category: "LegacyTech",
		Name:     "ColdFusion",
		Pattern:  `(?i)<cf(?:output|query|set|if|else|loop|include|module|form|mail).*?>|</?cfml>|\.cfm\b|\.cfc\b`,
	},
	{
		Category: "LegacyTech",
		Name:     "Perl CGI",
		Pattern:  `(?i)use\s+CGI(?:\s+qw|\s*;)|CGI::(?:param|header|cookie)|print\s+"Content-type:\s*text/html|#!/usr/bin/perl`,
	},
	{
		Category: "LegacyTech",
		Name:     "JSP Legacy",
		Pattern:  `(?i)<%@\s*page.*?%>|<%@\s*taglib.*?%>|<jsp:(?:include|forward|useBean|setProperty|getProperty)|\.jsp\b`,
	},
	{
		Category: "LegacyTech",
		Name:     "Struts1",
		Pattern:  `(?i)org\.apache\.struts\.action\.|struts-config\.xml|\.do\b|action\s*=\s*["'][^"']+\.do["']|extends\s+Action\b`,
	},

	// Legacy Web Technologies - Client Side
	{
		Category: "LegacyTech",
		Name:     "Silverlight",
		Pattern:  `(?i)Silverlight\.js|application/x-silverlight|\.xap\b|enableSilverlight|Silverlight\.createObject`,
	},
	{
		Category: "LegacyTech",
		Name:     "Flash",
		Pattern:  `(?i)\.swf\b|application/x-shockwave-flash|embedSWF|AC_FL_RunContent|Flash\.external|FlashVars`,
	},
	{
		Category: "LegacyTech",
		Name:     "VBScript",
		Pattern:  `(?i)<script.*?vbscript.*?>|window\.execScript|VBArray|On Error Resume Next|Set\s+\w+\s*=\s*CreateObject`,
	},

	// Legacy Frameworks and CMS
	{
		Category: "LegacyTech",
		Name:     "Rails Legacy",
		Pattern:  `(?i)rails/info/properties|rails/info/routes|RAILS_GEM_VERSION|config\.action_controller\.session|\.rhtml\b`,
	},
	{
		Category: "LegacyTech",
		Name:     "Drupal Legacy",
		Pattern:  `(?i)Drupal\.version|Drupal\.settings|drupal_add_js|drupal_add_css|sites/all/modules|/modules/node/node\.tpl\.php`,
	},
	{
		Category: "LegacyTech",
		Name:     "Zope",
		Pattern:  `(?i)zope\.interface|zope\.component|Products\.|ZODB\.|\.zcml\b|\.pt\b|\.cpt\b`,
	},
	{
		Category: "LegacyTech",
		Name:     "Smarty",
		Pattern:  `(?i){(?:include|if|foreach|assign|capture|php|literal|strip|block|extends).*?}|\.tpl\b|Smarty::PLUGINS_DIR`,
	},
	{
		Category: "LegacyTech",
		Name:     "Lotus Domino",
		Pattern:  `(?i)\.nsf\b|\.ntf\b|@Command|@DbLookup|@DbColumn|NotesDocument|NotesDatabase|\.ls[sx]\b`,
	},
	{
		Category: "LegacyTech",
		Name:     "Mod_perl",
		Pattern:  `(?i)use\s+Apache2?::|\bmod_perl\b|PerlModule\b|PerlRequire\b|PerlHandler\b`,
	},

	// Legacy Data Formats
	{
		Category: "LegacyTech",
		Name:     "XML Web",
		Pattern:  `(?i)text/xml|application/xml|xmlns:soap|<\?xml|<!DOCTYPE|<!ENTITY|SOAP-ENV:|\.xsl\b|\.xslt\b|\.wsdl\b`,
	},

	// Dangerous Functions
	{
		Category: "DangerousFunction",
		Name:     "JavaScript Eval",
		Pattern:  `(?i)eval\s*\([^)]*\)|new\s+Function\s*\([^)]*\)|setTimeout\s*\(\s*['"]|setInterval\s*\(\s*['"]`,
	},
	{
		Category: "DangerousFunction",
		Name:     "Python Execution",
		Pattern:  `(?i)(?:exec|eval|compile)\s*\([^)]*\)|__import__\s*\([^)]*\)|globals\s*\(\s*\)\s*\[[^\]]+\]`,
	},
	{
		Category: "DangerousFunction",
		Name:     "Shell Execution",
		Pattern:  `(?i)(?:os\.)?system\s*\([^)]*\)|subprocess\.(?:call|Popen|check_output|getoutput|getstatusoutput)\s*\([^)]*\)|popen\s*\([^)]*\)|shell_exec\s*\([^)]*\)`,
	},
	{
		Category: "DangerousFunction",
		Name:     "PHP Execution",
		Pattern:  `(?i)(?:shell_exec|exec|system|passthru|proc_open|popen|pcntl_exec)\s*\([^)]*\)|` + "`[^`]*`" + `|\$\([^)]*\)`,
	},
	{
		Category: "DangerousFunction",
		Name:     "Ruby Execution",
		Pattern:  `(?i)(?:eval|exec|system|syscall|` + "`[^`]*`" + `|\%x\{[^}]*\}|Open3\.(?:capture[23]|popen[23]|pipeline))\s*`,
	},

	// Rest of patterns remain unchanged...
	// [Previous patterns continue here...]
}
