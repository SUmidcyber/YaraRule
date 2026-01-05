rule Ransomware_Cryptocurrency_3aaf6d {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for ransomware: Cryptocurrency theft attacks traced to 2022 LastPass breach"
        reference = "https://www.bleepingcomputer.com/news/security/cryptocurrency-theft-attacks-traced-to-2022-lastpass-breach/"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 85
        mitre_techniques = "T1071, T1132, T1105, T1573, T1566"
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
        // MITRE ATT&CK Techniques: T1071, T1132, T1105
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            