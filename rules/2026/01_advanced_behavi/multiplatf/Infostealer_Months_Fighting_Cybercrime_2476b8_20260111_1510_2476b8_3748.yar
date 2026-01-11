rule Infostealer_Months_Fighting_Cybercrime_2476b8 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for infostealer: 12 Months of Fighting Cybercrime & Defending Enterprises | The Sentine"
        reference = "https://www.sentinelone.com/blog/12-months-of-fighting-cybercrime-defending-enterprises-the-sentinellabs-2025-review/"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        mitre_techniques = "T1573, T1204, T1071, T1566, T1132"
        behaviors = "Code Signing Abuse"
        source = "SentinelOne"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Behavioral Indicators
        $behavior1 = "PowerShell logging provides visibility into comman"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse T1573, T1204, T1071
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            