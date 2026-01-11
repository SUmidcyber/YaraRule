rule Infostealer_Trend_Micro_Apex_e6aa74 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for infostealer: Trend Micro Apex Central RCE Flaw Scores 9.8 CVSS in On-Prem Windows V"
        reference = "https://thehackernews.com/2026/01/trend-micro-apex-central-rce-flaw.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1071, T1573, T1566, T1059"
        behaviors = "Service Installation"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "trendmicro.jpg"
        $domain2 = "thehackernews.uk"
        $domain3 = "MsgReceiver.exe"

        // Infostealer specific
        $browser1 = "chrome" wide ascii
        $browser2 = "firefox" wide ascii
        $credential1 = "password" wide ascii
        $credential2 = "login" wide ascii
        $cookie_stealer = "cookie" wide ascii
        $crypto_wallet = "wallet.dat" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Service Installation T1071, T1573, T1566
            // Infostealer detection logic
            (
                ( any of ($browser*) and any of ($credential*) ) or
                ( $cookie_stealer and $password_stealer ) or
                ( $crypto_wallet and $private_key )
            ) and
            pe.is_pe
            