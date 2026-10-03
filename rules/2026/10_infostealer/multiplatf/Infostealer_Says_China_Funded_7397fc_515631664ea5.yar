rule Infostealer_Says_China_Funded_7397fc {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-03"
        description = "Detection for infostealer: MI5 Says China’s MSS Funded Research Involving 100+ U.K.-Linked Academ"
        reference = "https://thehackernews.com/2026/10/mi5-says-chinas-mss-funded-research.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "embassy.gov.cn" nocase
        $domain2 = "ukctransparency.substack.com" nocase
        $domain3 = "thehackernews.uk" nocase

    condition:
        any of ($domain*)
