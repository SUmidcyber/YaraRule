rule Infostealer_Malicious_Packages_Used_bc3ea3 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-29"
        description = "Advanced detection rule for infostealer: 27 Malicious npm Packages Used as Phishing Infrastructure to Steal Log"
        reference = "https://thehackernews.com/2025/12/27-malicious-npm-packages-used-as.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        mitre_techniques = "T1105, T1204, T1059, T1060, T1566"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "thehackernews.uk"
        $domain2 = "thehackernews.uk"
        $domain3 = "extension.html"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1105, T1204, T1059
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            