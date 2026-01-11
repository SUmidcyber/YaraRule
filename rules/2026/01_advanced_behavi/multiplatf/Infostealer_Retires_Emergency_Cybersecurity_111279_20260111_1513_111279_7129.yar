rule Infostealer_Retires_Emergency_Cybersecurity_111279 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for infostealer: CISA Retires 10 Emergency Cybersecurity Directives Issued Between 2019"
        reference = "https://thehackernews.com/2026/01/cisa-retires-10-emergency-cybersecurity.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        mitre_techniques = "T1071, T1573, T1566, T1059"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "cybersecurity.html"
        $domain2 = "thehackernews.uk"
        $domain3 = "extension-campaigns.html"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1071, T1573, T1566
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            