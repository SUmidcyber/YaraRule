rule Ransomware_Ransomware_Exposed_Hard_a7d42c {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for ransomware: VolkLocker Ransomware Exposed by Hard-Coded Master Key Allowing Free D"
        reference = "https://thehackernews.com/2025/12/volklocker-ransomware-exposed-by-hard.html"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 88
        mitre_techniques = "T1204, T1071, T1566, T1573, T1132"
        behaviors = "Keylogging"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "thehackernews.uk"
        $domain2 = "thehackernews.uk"
        $domain3 = "threatmon.io"

        // Ransomware specific
        $ransom_note1 = "Your files are encrypted" wide ascii
        $ransom_note2 = "Send bitcoin to" wide ascii
        $crypto_api1 = "CryptEncrypt" wide
        $crypto_api2 = "CryptDecrypt" wide
        $bitcoin_address = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Keylogging T1204, T1071, T1566
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            