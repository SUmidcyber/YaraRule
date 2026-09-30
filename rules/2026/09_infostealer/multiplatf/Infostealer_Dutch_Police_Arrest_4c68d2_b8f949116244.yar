rule Infostealer_Dutch_Police_Arrest_4c68d2 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-30"
        description = "Detection for infostealer: Dutch Police Arrest 24-Year-Old Amsterdam Man in ShinyHunters Investig"
        reference = "https://thehackernews.com/2026/09/dutch-police-arrest-24-year-old.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "krebsonsecurity.com" nocase
        $domain2 = "DataBreaches.Net" nocase
        $domain3 = "databreaches.net" nocase
        $domain4 = "thehackernews.uk" nocase

    condition:
        any of ($domain*)
