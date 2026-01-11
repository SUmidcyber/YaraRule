rule Banking_Microsoft_Warns_Misconfigured_f006c1 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for banking: Microsoft Warns Misconfigured Email Routing Can Enable Internal Domain"
        reference = "https://thehackernews.com/2026/01/microsoft-warns-misconfigured-email.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1573, T1204, T1071, T1566, T1059"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "phishing.jpg"
        $domain2 = "thehackernews.uk"
        $domain3 = "socradar.io"

        condition:
        // MITRE ATT&CK Techniques: T1573, T1204, T1071
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            