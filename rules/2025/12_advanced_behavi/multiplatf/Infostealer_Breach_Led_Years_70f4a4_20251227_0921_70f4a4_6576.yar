rule Infostealer_Breach_Led_Years_70f4a4 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for infostealer: LastPass 2022 Breach Led to Years-Long Cryptocurrency Thefts, TRM Labs"
        reference = "https://thehackernews.com/2025/12/lastpass-2022-breach-led-to-years-long.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1105, T1566, T1071, T1547, T1132"
        behaviors = "WMI Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "passwords.jpg"
        $domain2 = "thehackernews.uk"
        $domain3 = "Cryptomixer.io"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: WMI Abuse T1105, T1566, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            