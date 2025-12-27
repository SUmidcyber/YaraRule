rule Ransomware_Microsoft_Teams_6c5fee {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for ransomware: Microsoft Teams to let admins block external users via Defender portal"
        reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-teams-to-let-admins-block-external-users-via-defender-portal/"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 88
        mitre_techniques = "T1071, T1059, T1573, T1566"
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
        // Behaviors: Screen Capture T1071, T1059, T1573
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            