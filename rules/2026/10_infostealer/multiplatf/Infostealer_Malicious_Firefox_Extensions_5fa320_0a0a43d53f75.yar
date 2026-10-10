rule Infostealer_Malicious_Firefox_Extensions_5fa320 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for infostealer: 16 Malicious Firefox Extensions Pose as Rabby and OKX Wallets to Steal"
        reference = "https://thehackernews.com/2026/10/16-malicious-firefox-extensions-pose-as.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "riskyplugins.com" nocase
        $domain2 = "amibeingpwned.com" nocase
        $domain3 = "thehackernews.uk" nocase

    condition:
        any of ($domain*)
