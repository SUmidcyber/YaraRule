rule Banking_Nigeria_Microsoft_dcdcfa {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for banking: Nigeria arrests dev of Microsoft 365 'Raccoon0365' phishing platform"
        reference = "https://www.bleepingcomputer.com/news/security/nigeria-arrests-dev-of-microsoft-365-raccoon0365-phishing-platform/"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1566, T1071, T1573, T1125"
        behaviors = "N/A"
        source = "BleepingComputer"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        condition:
        // MITRE ATT&CK Techniques: T1566, T1071, T1573
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            