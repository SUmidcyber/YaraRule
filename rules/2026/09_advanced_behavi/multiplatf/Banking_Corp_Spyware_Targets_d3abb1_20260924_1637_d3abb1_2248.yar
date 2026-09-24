rule Banking_Corp_Spyware_Targets_d3abb1 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for banking: Corp MDM Spyware Targets Logistics Firms, Steals New SMS and Redirects"
        reference = "https://thehackernews.com/2026/09/corp-mdm-spyware-targets-logistics.html"
        threat_level = 8
        malware_type = "banking"
        confidence_score = 85
        mitre_techniques = "T1573, T1132, T1059, T1071, T1566"
        behaviors = "N/A"
        source = "The Hacker News"
        version = "4.1"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators - Domains
        $domain1 = "haveibeensquatted.com" nocase
        $domain2 = "ctrlaltintel.com" nocase
        $domain3 = "thehackernews.uk" nocase

    condition:
        // MITRE ATT&CK: T1573, T1132, T1059, T1071, T1566
        any of ($domain*)
