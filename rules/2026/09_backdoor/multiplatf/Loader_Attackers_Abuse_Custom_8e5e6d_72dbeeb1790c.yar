rule Loader_Attackers_Abuse_Custom_8e5e6d {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-30"
        description = "Detection for loader: Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix Lures"
        reference = "https://thehackernews.com/2026/09/attackers-abuse-chatgpt-custom-gpts-to.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "6ab595ad6554819181b686d4876efb80"
        $hash2 = "6ab6ba039440819185ed491740b11cf8"

        // Domains
        $domain1 = "binarydefense.com" nocase
        $domain2 = "thehackernews.uk" nocase

    condition:
        (( any of ($hash*) and any of ($domain*) )) and filesize < 10MB
