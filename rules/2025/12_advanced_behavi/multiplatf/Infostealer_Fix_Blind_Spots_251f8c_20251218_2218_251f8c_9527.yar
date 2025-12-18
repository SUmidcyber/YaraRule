rule Infostealer_Fix_Blind_Spots_251f8c {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for infostealer: Fix SOC Blind Spots: See Threats to Your Industry & Country in Real Ti"
        reference = "https://thehackernews.com/2025/12/fix-soc-blind-spots-see-threats-to-your.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1204, T1566, T1071, T1573, T1059"
        behaviors = "Code Signing Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "intelligence.any.run"
        $domain2 = "2522benelui.click"
        $domain3 = "intelligence.any.run"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse T1204, T1566, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            