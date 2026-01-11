rule Ransomware_Webinar_Learn_How_b3d031 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for ransomware: Webinar: Learn How AI-Powered Zero Trust Detects Attacks with No Files"
        reference = "https://thehackernews.com/2026/01/webinar-learn-how-ai-powered-zero-trust.html"
        threat_level = 9
        malware_type = "ransomware"
        confidence_score = 95
        mitre_techniques = "T1573, T1204, T1071, T1566, T1132"
        behaviors = "WMI Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "thehacker.news"
        $domain2 = "thehacker.news"
        $domain3 = "thehacker.news"

        // Behavioral Indicators
        $behavior1 = "PowerShell, WMI, or remote desktop. File-based det"

        // Ransomware specific
        $ransom_note1 = "Your files are encrypted" wide ascii
        $ransom_note2 = "Send bitcoin to" wide ascii
        $crypto_api1 = "CryptEncrypt" wide
        $crypto_api2 = "CryptDecrypt" wide
        $bitcoin_address = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: WMI Abuse T1573, T1204, T1071
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            