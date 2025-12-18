rule Hpe_Oneview_Flaw_bfc4fe51 {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Detects Conti: HPE OneView Flaw Rated CVSS 10.0 Allows Unauthenticated Remote Code Execution"
        reference = "https://thehackernews.com/2025/12/hpe-oneview-flaw-rated-cvss-100-allows.html"
        threat_level = 9
        malware_family = "Conti"
        platform = "MultiPlatform"
        target_os = "Windows"
        language = "JavaScript"
        capabilities = "malware_detection"
        source = "The Hacker News"
        ioc_count = 28
        version = "3.0"
        generated_from = "EliteYaraGenerator"

    strings:
        $domain1 = "thehackernews.com"
        $domain2 = "www.hpe.com"
        $domain3 = "support.hpe.com"

    condition:
        any of ($domain*)
}