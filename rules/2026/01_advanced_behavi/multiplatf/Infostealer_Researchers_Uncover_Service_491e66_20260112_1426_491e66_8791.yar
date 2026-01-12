rule Infostealer_Researchers_Uncover_Service_491e66 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-12"
        description = "Advanced detection rule for infostealer: Researchers Uncover Service Providers Fueling Industrial-Scale Pig But"
        reference = "https://thehackernews.com/2026/01/researchers-uncover-service-providers.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1204, T1573, T1059, T1071, T1566"
        behaviors = "Code Signing Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "service-providers.html"
        $domain2 = "rescues-250-citizens.html"
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
        // Behaviors: Code Signing Abuse T1204, T1573, T1059
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            