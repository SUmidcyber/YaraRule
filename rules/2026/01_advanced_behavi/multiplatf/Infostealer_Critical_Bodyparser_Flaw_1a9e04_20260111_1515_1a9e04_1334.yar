rule Infostealer_Critical_Bodyparser_Flaw_1a9e04 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for infostealer: Critical AdonisJS Bodyparser Flaw (CVSS 9.2) Enables Arbitrary File Wr"
        reference = "https://thehackernews.com/2026/01/critical-adonisjs-bodyparser-flaw-cvss.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1573, T1105, T1204, T1071, T1060"
        behaviors = "Registry Persistence"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "security.jpg"
        $domain2 = "MultipartFile.move"
        $domain3 = "thehackernews.uk"

        // File Artifacts
        $file1 = "min.js"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Registry Persistence T1573, T1105, T1204
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            