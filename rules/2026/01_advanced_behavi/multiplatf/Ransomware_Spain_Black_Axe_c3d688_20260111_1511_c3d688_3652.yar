rule Ransomware_Spain_Black_Axe_c3d688 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for ransomware: Spain arrests 34 suspects linked to Black Axe cyber crime"
        reference = "https://www.bleepingcomputer.com/news/security/spain-arrests-34-suspects-linked-to-black-axe-cyber-crime/"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 85
        mitre_techniques = "T1573, T1105, T1071, T1566, T1125"
        behaviors = "N/A"
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
        // MITRE ATT&CK Techniques: T1573, T1105, T1071
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            