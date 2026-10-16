rule Infostealer_Patches_Upload_Flaw_ce90da {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for infostealer: curl Patches HTTP/2 Upload Flaw After PoC Demonstrates Client-Side Cod"
        reference = "https://thehackernews.com/2026/10/curl-patches-http2-upload-flaw-after.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "8b0744af5b1b631da5b938ca31c3f9895ad5a321"

        // Domains
        $domain1 = "hackerone.com" nocase
        $domain2 = "thehackernews.uk" nocase

    condition:
        ( any of ($hash*) and any of ($domain*) )
