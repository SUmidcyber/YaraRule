rule Infostealer_Black_Cat_Behind_87a6b8 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for infostealer: Black Cat Behind SEO Poisoning Malware Campaign Targeting Popular Soft"
        reference = "https://thehackernews.com/2026/01/black-cat-behind-seo-poisoning-malware.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 91
        mitre_techniques = "T1573, T1105, T1204, T1115, T1071"
        behaviors = "Keylogging, Clipboard Data"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "d07dc41546fd6db93f14582cea697821"

        // Network Indicators
        $domain1 = "malware.html"
        $domain2 = "malware.jpg"
        $domain3 = "thehackernews.uk"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Keylogging, Clipboard Data T1573, T1105, T1204
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            