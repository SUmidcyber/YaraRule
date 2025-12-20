rule Infostealer_Charges_Jackpotting_Scheme_052760 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for infostealer: U.S. DOJ Charges 54 in ATM Jackpotting Scheme Using Ploutus Malware"
        reference = "https://thehackernews.com/2025/12/us-doj-charges-54-in-atm-jackpotting.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 91
        mitre_techniques = "T1059, T1071, T1573, T1566, T1204"
        behaviors = "PowerShell Download & Execute, Keylogging"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "jackpotting.html"
        $domain2 = "thehackernews.uk"
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
        // Behaviors: PowerShell Download & Execute, Keylogging T1059, T1071, T1573
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            