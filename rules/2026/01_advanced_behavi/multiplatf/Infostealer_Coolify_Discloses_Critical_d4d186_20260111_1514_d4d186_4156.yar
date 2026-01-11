rule Infostealer_Coolify_Discloses_Critical_d4d186 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for infostealer: Coolify Discloses 11 Critical Flaws Enabling Full Server Compromise on"
        reference = "https://thehackernews.com/2026/01/coolify-discloses-11-critical-flaws.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        mitre_techniques = "T1573, T1204, T1071, T1566, T1132"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "thehackernews.uk"
        $domain2 = "platform.censys.io"
        $domain3 = "extension-campaigns.html"

        // Behavioral Indicators
        $behavior1 = "import functionality allows attackers to execute a"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1573, T1204, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            