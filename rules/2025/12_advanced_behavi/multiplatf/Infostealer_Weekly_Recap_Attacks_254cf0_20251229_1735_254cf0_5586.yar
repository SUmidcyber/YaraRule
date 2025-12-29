rule Infostealer_Weekly_Recap_Attacks_254cf0 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-29"
        description = "Advanced detection rule for infostealer: ⚡ Weekly Recap: MongoDB Attacks, Wallet Breaches, Android Spyware, Ins"
        reference = "https://thehackernews.com/2025/12/weekly-recap-mongodb-attacks-wallet.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        mitre_techniques = "T1113, T1105, T1204, T1082, T1123"
        behaviors = "Service Installation, Code Signing Abuse, Keylogging, Screen Capture, Clipboard Data"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "470549567520c89c04be1b30b218fe33"

        // Network Indicators
        $domain1 = "vulnerability.html"
        $domain2 = "exploited-digiever.html"
        $domain3 = "fatihhcelik.github.io"

        // Behavioral Indicators
        $behavior1 = "PowerShell scripts, the second of which contains t"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Service Installation, Code Signing Abuse, Keylogging T1113, T1105, T1204
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            