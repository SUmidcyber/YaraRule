rule Infostealer_Docker_Fixes_Critical_26fd70 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for infostealer: Docker Fixes Critical Two-Year-Old Hub Flaw That Let One User Push Ima"
        reference = "https://thehackernews.com/2026/10/docker-fixes-critical-two-year-old-hub.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "1ebe400624597c82a7a32e330315c9aae8d32429"
        $hash2 = "0c89cc74132d74f7aa4afd0e859da2109d4bef59"

        // Domains
        $domain1 = "thehackernews.uk" nocase

    condition:
        ( any of ($hash*) and any of ($domain*) )
