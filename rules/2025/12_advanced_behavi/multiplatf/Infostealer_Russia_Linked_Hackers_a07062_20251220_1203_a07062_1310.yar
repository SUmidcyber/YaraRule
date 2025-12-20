rule Infostealer_Russia_Linked_Hackers_a07062 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for infostealer: Russia-Linked Hackers Use Microsoft 365 Device Code Phishing for Accou"
        reference = "https://thehackernews.com/2025/12/russia-linked-hackers-use-microsoft-365.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        mitre_techniques = "T1059, T1071, T1573, T1189, T1566"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "microsoft-365.html"
        $domain2 = "thehackernews.uk"
        $domain3 = "hackers-using.html"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1059, T1071, T1573
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            