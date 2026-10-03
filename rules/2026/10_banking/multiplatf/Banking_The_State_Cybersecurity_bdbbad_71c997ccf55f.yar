rule Banking_The_State_Cybersecurity_bdbbad {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-03"
        description = "Detection for banking: The State of Cybersecurity in 2026: Key Segments, Insights, and Innova"
        reference = "https://thehackernews.com/2026/10/the-state-of-cybersecurity-in-2026key.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "keepersecurity.com" nocase
        $domain2 = "adaptivesecurity.com" nocase
        $domain3 = "thehackernews.uk" nocase

    condition:
        any of ($domain*)
