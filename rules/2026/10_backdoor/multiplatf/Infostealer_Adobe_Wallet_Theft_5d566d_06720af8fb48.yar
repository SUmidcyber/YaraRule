rule Infostealer_Adobe_Wallet_Theft_5d566d {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for infostealer: ThreatsDay: Adobe RCE, DNS Wallet Theft, NVIDIA Container Escape, Self"
        reference = "https://thehackernews.com/2026/10/threatsday-adobe-rce-dns-wallet-theft.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "05789e67c5d022f2403b9340fc8d82dc99dc3707"

        // Domains
        $domain1 = "easyllms.xyz" nocase
        $domain2 = "thehackernews.uk" nocase

    condition:
        ( any of ($hash*) and any of ($domain*) )
