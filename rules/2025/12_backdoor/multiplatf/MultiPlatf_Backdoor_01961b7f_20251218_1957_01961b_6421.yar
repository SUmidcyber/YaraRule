rule MultiPlatf_Backdoor_01961b7f {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Detects Backdoor: France arrests suspect tied to cyberattack on Interior Ministry"
        reference = "https://www.bleepingcomputer.com/news/security/france-arrests-suspect-tied-to-cyberattack-on-interior-ministry/"
        threat_level = 3
        malware_family = "Generic"
        platform = "MultiPlatform"
        category = "Backdoor"
        source = "Unknown"
        version = "1.0"
        auto_generated = true

    strings:
        $s1 = "-old" nocase // Extracted from article
        $s2 = "cyberattack" nocase // Extracted from article
        $s3 = "authorities" nocase // Extracted from article
        $s4 = "-year" nocase // Extracted from article
        $g1 = "malware" nocase
        $g2 = "trojan" nocase
        $g3 = "exploit" nocase
        $g4 = "payload" nocase
        $g5 = "c2" nocase
        $g6 = "server" nocase

    condition:
        (3 of ($s*) and 1 of ($g*)) or (filesize < 5MB and 2 of ($s*))
}