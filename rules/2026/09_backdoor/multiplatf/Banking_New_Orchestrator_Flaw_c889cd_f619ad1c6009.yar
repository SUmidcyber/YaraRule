rule Banking_New_Orchestrator_Flaw_c889cd {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Detection for banking: New CVSS 10.0 VeloCloud Orchestrator Flaw Actively Exploited in Certif"
        reference = "https://thehackernews.com/2026/09/new-cvss-100-velocloud-orchestrator.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "dc78e206eaeadec59fc5801fe4556bd0"

        // Domains
        $domain1 = "thehackernews.uk" nocase

        // IPs
        $ip1 = "5.2.3.15"
        $ip2 = "5.2.3.16"
        $ip3 = "5.2.3.14"

    condition:
        2 of ($hash*, $domain*, $ip*)
