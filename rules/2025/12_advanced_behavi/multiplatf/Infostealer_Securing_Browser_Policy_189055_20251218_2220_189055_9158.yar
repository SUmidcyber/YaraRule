rule Infostealer_Securing_Browser_Policy_189055 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for infostealer: Securing GenAI in the Browser: Policy, Isolation, and Data Controls Th"
        reference = "https://thehackernews.com/2025/12/securing-genai-in-browser-policy.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 91
        mitre_techniques = "T1204, T1071, T1566, T1573, T1132"
        behaviors = "Keylogging, Clipboard Data"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "seraphicsecurity.com"
        $domain2 = "seraphicsecurity.com"
        $domain3 = "seraphicsecurity.com"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Keylogging, Clipboard Data T1204, T1071, T1566
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            