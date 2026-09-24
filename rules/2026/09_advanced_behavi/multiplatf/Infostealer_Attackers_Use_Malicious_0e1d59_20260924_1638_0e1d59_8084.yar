rule Infostealer_Attackers_Use_Malicious_0e1d59 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for infostealer: Attackers Use Malicious Terraform Providers to Deliver Go Malware via "
        reference = "https://thehackernews.com/2026/09/attackers-use-malicious-terraform.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        mitre_techniques = "T1573, T1132, T1105, T1059, T1082"
        behaviors = "Clipboard Data"
        source = "The Hacker News"
        version = "4.1"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators - Domains
        $domain1 = "conversations.history" nocase
        $domain2 = "kudelskisecurity.com" nocase
        $domain3 = "thehackernews.uk" nocase

        // Infostealer specific
        $browser1 = "chrome" wide ascii nocase
        $browser2 = "firefox" wide ascii nocase
        $credential1 = "password" wide ascii nocase
        $credential2 = "login" wide ascii nocase
        $cookie_stealer1 = "cookie" wide ascii nocase
        $crypto_wallet1 = "wallet.dat" wide ascii nocase

    condition:
        // MITRE ATT&CK: T1573, T1132, T1105, T1059, T1082
        // Behaviors: Clipboard Data
        (
                any of ($domain*) or
                any of ($browser*) or
                any of ($credential*) or
                any of ($cookie_stealer*) or
                any of ($crypto_wallet*)
            )
