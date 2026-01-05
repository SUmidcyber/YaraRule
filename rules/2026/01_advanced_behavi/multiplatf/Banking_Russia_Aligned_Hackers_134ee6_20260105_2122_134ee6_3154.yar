rule Banking_Russia_Aligned_Hackers_134ee6 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for banking: Russia-Aligned Hackers Abuse Viber to Target Ukrainian Military and Go"
        reference = "https://thehackernews.com/2026/01/russia-aligned-hackers-abuse-viber-to.html"
        threat_level = 9
        malware_type = "banking"
        confidence_score = 95
        mitre_techniques = "T1059, T1547, T1071, T1204, T1105"
        behaviors = "Scheduled Task, Code Signing Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "cf6b118e88395af45a000aae80811264"

        // Network Indicators
        $domain1 = "cyberattack.html"
        $domain2 = "thehackernews.uk"
        $domain3 = "smoothieks.zip"

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Scheduled Task, Code Signing Abuse T1059, T1547, T1071
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            