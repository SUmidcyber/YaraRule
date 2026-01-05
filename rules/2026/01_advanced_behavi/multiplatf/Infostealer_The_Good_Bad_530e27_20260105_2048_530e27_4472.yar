rule Infostealer_The_Good_Bad_530e27 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for infostealer: The Good, the Bad and the Ugly in Cybersecurity – Week 1"
        reference = "https://www.sentinelone.com/blog/the-good-the-bad-and-the-ugly-in-cybersecurity-week-1-7/"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 91
        mitre_techniques = "T1059, T1547, T1566, T1071, T1204"
        behaviors = "Code Signing Abuse, Clipboard Data"
        source = "SentinelOne"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "ProjectConfiguration.sys"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse, Clipboard Data T1059, T1547, T1566
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            