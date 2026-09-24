rule Infostealer_Weekly_Recap_Cisco_fa149a {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Detection for infostealer: ⚡ Weekly Recap: Cisco 0-Day, AI Agent RCE, ClickFix Attacks, ClickFix "
        reference = "https://thehackernews.com/2026/09/weekly-recap-cisco-0-day-ai-agent-rce.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "thehackernews.uk" nocase
        $domain2 = "chromereleases.googleblog.com" nocase
        $domain3 = "thehacker.news" nocase
        $domain4 = "www.ransomware.live" nocase

    condition:
        any of ($domain*)
