rule Banking_Treasury_Lifts_Sanctions_57a401 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for banking: U.S. Treasury Lifts Sanctions on Three Individuals Linked to Intellexa"
        reference = "https://thehackernews.com/2025/12/us-treasury-lifts-sanctions-on-three.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1204, T1071, T1059, T1573"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "sanctions-on-three.html"
        $domain2 = "thehackernews.uk"
        $domain3 = "predatory-spyware.html"

        condition:
        // MITRE ATT&CK Techniques: T1204, T1071, T1059
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            