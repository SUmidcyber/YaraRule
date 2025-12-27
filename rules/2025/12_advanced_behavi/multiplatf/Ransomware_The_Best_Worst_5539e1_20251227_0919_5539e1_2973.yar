rule Ransomware_The_Best_Worst_5539e1 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for ransomware: The Best, the Worst and the Ugliest in Cybersecurity | 2025 Edition"
        reference = "https://www.sentinelone.com/blog/the-best-the-worst-and-the-ugliest-in-cybersecurity-2025-edition/"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 85
        mitre_techniques = "T1566, T1071, T1060, T1132, T1573"
        behaviors = "N/A"
        source = "SentinelOne"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Ransomware specific
        $ransom_note1 = "Your files are encrypted" wide ascii
        $ransom_note2 = "Send bitcoin to" wide ascii
        $crypto_api1 = "CryptEncrypt" wide
        $crypto_api2 = "CryptDecrypt" wide
        $bitcoin_address = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

        condition:
        // MITRE ATT&CK Techniques: T1566, T1071, T1060
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            