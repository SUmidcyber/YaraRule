rule Infostealer_Says_China_Linked_57e240 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for infostealer: FBI Says China-Linked Hackers Ran Portal Giving Third Parties Access t"
        reference = "https://thehackernews.com/2026/10/fbi-says-china-linked-hackers-ran.html"
        threat_level = 9
        malware_type = "infostealer"
        confidence_score = 95
        source = "The Hacker News"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "903fe5ab7a275bd69c3c3346af2d21cf87ebeabf"

        // Domains
        $domain1 = "thehackernews.uk" nocase

        // IPs
        $ip1 = "2.3.20.2"
        $ip2 = "2.3.24.1"
        $ip3 = "2.3.20.3"

        // Files
        $file1 = "DC.exe" nocase

    condition:
        2 of ($hash*, $domain*, $ip*, $file*)
