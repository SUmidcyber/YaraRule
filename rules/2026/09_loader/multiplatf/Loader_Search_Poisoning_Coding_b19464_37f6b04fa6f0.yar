rule Loader_Search_Poisoning_Coding_b19464 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Detection for loader: ThreatsDay: AI Search Poisoning, AI Coding Tool Leaking Repos, One-Cli"
        reference = "https://thehackernews.com/2026/09/threatsday-ai-search-poisoning-ai.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 94
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "www.malwarebytes.com" nocase
        $domain2 = "Exploit.in" nocase
        $domain3 = "adminmenueditor.com" nocase
        $domain4 = "thehackernews.uk" nocase

        // Files
        $file1 = "payload.js" nocase

    condition:
        (( any of ($domain*) and any of ($file*) )) and filesize < 10MB
