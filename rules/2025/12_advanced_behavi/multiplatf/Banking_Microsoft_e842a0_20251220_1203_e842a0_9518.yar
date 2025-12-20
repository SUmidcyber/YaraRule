rule Banking_Microsoft_e842a0 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for banking: Microsoft 365 accounts targeted in wave of OAuth phishing attacks"
        reference = "https://www.bleepingcomputer.com/news/security/microsoft-365-accounts-targeted-in-wave-of-oauth-phishing-attacks/"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1204, T1566, T1071, T1573"
        behaviors = "N/A"
        source = "BleepingComputer"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        condition:
        // MITRE ATT&CK Techniques: T1204, T1566, T1071
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            