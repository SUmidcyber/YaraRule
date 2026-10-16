rule Loader_Weekly_Recap_Helpdesk_d4de3e {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for loader: ⚡ Weekly Recap: Helpdesk 0-Days, Rogue Certs, ShinyHunters Arrest, AI-"
        reference = "https://thehackernews.com/2026/10/weekly-recap-helpdesk-0-days-rogue.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "thehackernews.uk" nocase
        $domain2 = "www.integritytech.com.cn" nocase
        $domain3 = "nattothoughts.substack.com" nocase
        $domain4 = "krebsonsecurity.com" nocase
        $domain5 = "chromereleases.googleblog.com" nocase

    condition:
        (any of ($domain*)) and filesize < 10MB
