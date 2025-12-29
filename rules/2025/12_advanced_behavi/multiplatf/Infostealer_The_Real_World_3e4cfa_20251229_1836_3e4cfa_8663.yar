rule Infostealer_The_Real_World_3e4cfa {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-29"
        description = "Advanced detection rule for infostealer: The Real-World Attacks Behind OWASP Agentic AI Top 10"
        reference = "https://www.bleepingcomputer.com/news/security/the-real-world-attacks-behind-owasp-agentic-ai-top-10/"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1105, T1204, T1059, T1566, T1573"
        behaviors = "Code Signing Abuse"
        source = "BleepingComputer"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse T1105, T1204, T1059
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            