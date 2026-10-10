rule Loader_Tensorlake_Package_Compromised_49ccaa {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for loader: Tensorlake npm Package Compromised to Deliver Shai-Hulud Credential-St"
        reference = "https://thehackernews.com/2026/10/tensorlake-npm-package-compromised-to.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "e90c47bbb208e99cac8aa678405b2133f6cb3f52"
        $hash2 = "6386121c561e74fec143a138d5cc3d3bbabdfe8c"

        // Domains
        $domain1 = "thehackernews.uk" nocase

    condition:
        (( any of ($hash*) and any of ($domain*) )) and filesize < 10MB
