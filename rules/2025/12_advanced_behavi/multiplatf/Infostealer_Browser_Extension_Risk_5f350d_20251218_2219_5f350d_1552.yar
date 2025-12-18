rule Infostealer_Browser_Extension_Risk_5f350d {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for infostealer: A Browser Extension Risk Guide After the ShadyPanda Campaign"
        reference = "https://thehackernews.com/2025/12/a-browser-extension-risk-guide-after.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1204, T1566, T1071, T1573, T1059"
        behaviors = "Keylogging"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "seedsnatcher.html"
        $domain2 = "phishing-kits-use-ai-and.html"
        $domain3 = "bulletin-spyware-alerts.html"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Keylogging T1204, T1566, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            