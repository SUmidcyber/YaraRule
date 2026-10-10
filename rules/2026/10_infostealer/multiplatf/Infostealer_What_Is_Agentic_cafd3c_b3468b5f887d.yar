rule Infostealer_What_Is_Agentic_cafd3c {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for infostealer: What Is Agentic Pentesting? What It Proves, and Where It Stops."
        reference = "https://thehackernews.com/2026/10/what-is-agentic-pentesting-what-it.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "jerrygamblin.com" nocase
        $domain2 = "zerodayclock.com" nocase
        $domain3 = "thehackernews.uk" nocase

    condition:
        any of ($domain*)
