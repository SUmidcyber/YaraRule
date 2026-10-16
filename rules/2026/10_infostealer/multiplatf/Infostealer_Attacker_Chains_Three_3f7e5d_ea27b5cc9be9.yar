rule Infostealer_Attacker_Chains_Three_3f7e5d {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for infostealer: Attacker Chains Three Ivanti Connect Secure Zero-Days for Root Access,"
        reference = "https://thehackernews.com/2026/10/attacker-chains-three-ivanti-connect.html"
        threat_level = 8
        malware_type = "infostealer"
        confidence_score = 88
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Domains
        $domain1 = "thehackernews.uk" nocase

        // IPs
        $ip1 = "25.1.3.0"
        $ip2 = "25.1.3.1"

    condition:
        ( any of ($domain*) and any of ($ip*) )
