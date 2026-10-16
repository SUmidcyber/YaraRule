rule Loader_Hackers_Backdoor_Nextcloud_fb12e5 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for loader: Hackers Backdoor Nextcloud Servers Through Critical Flaw in Collabora’"
        reference = "https://thehackernews.com/2026/10/hackers-backdoor-nextcloud-servers.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 91
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "6cc8dae54c92bae27d53c54b9898cf1123ca2066"
        $hash2 = "4b9fbd0663fbfd6028fc216ed18e0d6ef3ae498a7fdc97083e4b0ce3cec40562"

        // Domains
        $domain1 = "thehackernews.uk" nocase

    condition:
        (( any of ($hash*) and any of ($domain*) )) and filesize < 10MB
