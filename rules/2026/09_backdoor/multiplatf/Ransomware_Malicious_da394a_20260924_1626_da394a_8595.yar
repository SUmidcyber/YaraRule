rule Ransomware_Malicious_da394a {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for ransomware: Malicious npm campaign targets developers integrating Twilio"
        reference = "https://www.reversinglabs.com/blog/malicious-npm-campaign-twilio"
        threat_level = 6
        malware_type = "ransomware"
        confidence_score = 65
        mitre_techniques = "N/A"
        behaviors = "N/A"
        source = "ReversingLabs Blog"
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
            // Ransomware detection logic
            ( 
                ( any of ($crypto*) and any of ($ransom_note*) ) or
                ( 2 of ($file_encryption*) and $bitcoin_address )
            ) and 
            filesize < 10MB
            