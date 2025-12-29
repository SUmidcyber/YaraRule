rule Ransomware_Former_Coinbase_82df64 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-29"
        description = "Advanced detection rule for ransomware: Former Coinbase support agent arrested for helping hackers"
        reference = "https://www.bleepingcomputer.com/news/security/former-coinbase-support-agent-arrested-for-helping-hackers/"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 80
        mitre_techniques = "T1566, T1573, T1071"
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
        // MITRE ATT&CK Techniques: T1566, T1573, T1071
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            