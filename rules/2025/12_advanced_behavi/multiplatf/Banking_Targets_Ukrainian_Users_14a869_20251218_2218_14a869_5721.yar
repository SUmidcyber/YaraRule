rule Banking_Targets_Ukrainian_Users_14a869 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for banking: APT28 Targets Ukrainian UKR-net Users in Long-Running Credential Phish"
        reference = "https://thehackernews.com/2025/12/apt28-targets-ukrainian-ukr-net-users.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1204, T1566, T1071, T1573, T1059"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "thehackernews.uk"
        $domain2 = "agencies-warn-ubiquiti.html"
        $domain3 = "seedsnatcher.html"

        condition:
        // MITRE ATT&CK Techniques: T1204, T1566, T1071
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            