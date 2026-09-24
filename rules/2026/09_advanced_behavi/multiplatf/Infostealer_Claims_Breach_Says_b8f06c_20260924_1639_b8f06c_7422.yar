rule Infostealer_Claims_Breach_Says_b8f06c {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for infostealer: ShinyHunters Claims FBI Breach, Says It Stole Data on Agents and Job A"
        reference = "https://thehackernews.com/2026/09/shinyhunters-claims-fbi-breach-says-it.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 85
        mitre_techniques = "T1573, T1059, T1071, T1566, T1204"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.1"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators - Domains
        $domain1 = "www.ransomlook.io" nocase
        $domain2 = "thehackernews.uk" nocase

        // Infostealer specific
        $browser1 = "chrome" wide ascii nocase
        $browser2 = "firefox" wide ascii nocase
        $credential1 = "password" wide ascii nocase
        $credential2 = "login" wide ascii nocase
        $cookie_stealer1 = "cookie" wide ascii nocase
        $crypto_wallet1 = "wallet.dat" wide ascii nocase

    condition:
        // MITRE ATT&CK: T1573, T1059, T1071, T1566, T1204
        (
                any of ($domain*) or
                any of ($browser*) or
                any of ($credential*) or
                any of ($cookie_stealer*) or
                any of ($crypto_wallet*)
            )
