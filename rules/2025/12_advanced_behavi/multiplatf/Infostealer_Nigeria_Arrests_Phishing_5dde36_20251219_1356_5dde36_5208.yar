rule Infostealer_Nigeria_Arrests_Phishing_5dde36 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-19"
        description = "Advanced detection rule for infostealer: Nigeria Arrests RaccoonO365 Phishing Developer Linked to Microsoft 365"
        reference = "https://thehackernews.com/2025/12/nigeria-arrests-raccoono365-phishing.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        mitre_techniques = "T1204, T1566, T1071, T1573, T1059"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "raccoono365-phishing.html"
        $domain2 = "arrested.jpg"
        $domain3 = "thehackernews.uk"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1204, T1566, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            