rule Banking_Cybercriminals_Abuse_Google_e5525f {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for banking: Cybercriminals Abuse Google Cloud Email Feature in Multi-Stage Phishin"
        reference = "https://thehackernews.com/2026/01/cybercriminals-abuse-google-cloud-email.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1059, T1071, T1204, T1132, T1573"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "thehackernews.uk"
        $domain2 = "thehackernews.uk"
        $domain3 = "ravenmail.io"

        condition:
        // MITRE ATT&CK Techniques: T1059, T1071, T1204
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            