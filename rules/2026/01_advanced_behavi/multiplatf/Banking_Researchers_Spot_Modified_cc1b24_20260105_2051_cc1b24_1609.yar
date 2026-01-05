rule Banking_Researchers_Spot_Modified_cc1b24 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for banking: Researchers Spot Modified Shai-Hulud Worm Testing Payload on npm Regis"
        reference = "https://thehackernews.com/2025/12/researchers-spot-modified-shai-hulud.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1059, T1547, T1071, T1204, T1132"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "8bce95ebfb895537fec243e069d7193980361de9d916339906b11a14ffded94f"
        $hash2 = "702161756dfd150ad3c214fbf97ce98fdc960ea7b3970b5300702ed8c953cafd"

        // Network Indicators
        $domain1 = "thehackernews.uk"
        $domain2 = "sequence.com"
        $domain3 = "3nvir0nm3nt.json"

        condition:
        // MITRE ATT&CK Techniques: T1059, T1547, T1071
            // Generic malware detection
            any of ($malicious*) or 
            ( 2 of ($suspicious*) and $anomaly ) or
            ( $packed and $obfuscated )
            