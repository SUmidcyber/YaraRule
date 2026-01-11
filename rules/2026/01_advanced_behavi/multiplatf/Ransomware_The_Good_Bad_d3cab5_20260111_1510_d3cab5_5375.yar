rule Ransomware_The_Good_Bad_d3cab5 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for ransomware: The Good, the Bad and the Ugly in Cybersecurity – Week 2"
        reference = "https://www.sentinelone.com/blog/the-good-the-bad-and-the-ugly-in-cybersecurity-week-2-7/"
        threat_level = 8
        malware_type = "ransomware"
        confidence_score = 85
        mitre_techniques = "T1573, T1204, T1071, T1132, T1547"
        behaviors = "N/A"
        source = "SentinelOne"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "developer.mozilla.org"
        $domain2 = "conflusion-ni8mare.jpg"

        // Ransomware specific
        $ransom_note1 = "Your files are encrypted" wide ascii
        $ransom_note2 = "Send bitcoin to" wide ascii
        $crypto_api1 = "CryptEncrypt" wide
        $crypto_api2 = "CryptDecrypt" wide
        $bitcoin_address = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/

        condition:
        // MITRE ATT&CK Techniques: T1573, T1204, T1071
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            