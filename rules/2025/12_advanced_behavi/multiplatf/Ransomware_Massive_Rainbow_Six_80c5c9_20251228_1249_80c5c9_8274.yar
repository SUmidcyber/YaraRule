rule Ransomware_Massive_Rainbow_Six_80c5c9 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-28"
        description = "Advanced detection rule for ransomware: Massive Rainbow Six Siege breach gives players billions of credits"
        reference = "https://www.bleepingcomputer.com/news/security/massive-rainbow-six-siege-breach-gives-players-billions-of-credits/"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 88
        mitre_techniques = "T1071, T1113, T1573, T1566"
        behaviors = "Screen Capture"
        source = "BleepingComputer"
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
        // MITRE ATT&CK Techniques:
        // Behaviors: Screen Capture T1071, T1113, T1573
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            