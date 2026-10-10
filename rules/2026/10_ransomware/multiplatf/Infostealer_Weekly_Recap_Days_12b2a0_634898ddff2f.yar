rule Infostealer_Weekly_Recap_Days_12b2a0 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for infostealer: ⚡ Weekly Recap: NetScaler and FortiMail 0-Days, AI Coding Leaks, Spect"
        reference = "https://thehackernews.com/2026/10/weekly-recap-netscaler-and-fortimail-0.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "1820a349687522f51023d1ae5925125f59679a8c"

        // Domains
        $domain1 = "thehackernews.uk" nocase
        $domain2 = "securitylabs.datadoghq.com" nocase
        $domain3 = "ridgesecurity.ai" nocase
        $domain4 = "minanagehsalalma.github.io" nocase
        $domain5 = "chromereleases.googleblog.com" nocase

    condition:
        ( any of ($hash*) and any of ($domain*) )
