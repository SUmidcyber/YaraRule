rule MultiPlatf_Backdoor_Conti_2025 {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Detects Backdoor malware: France arrests Latvian for installing malware on Italian ferry"
        reference = "https://www.bleepingcomputer.com/news/security/france-arrests-latvian-for-installing-malware-on-italian-ferry/"
        threat_level = 5
        malware_family = "Conti"
        platform = "MultiPlatform"
        source = "Unknown"
        created_by = "AutoYaraBot v2.0"

    strings:
        $s1 = "malware" nocase // Generic malware indicator
        $s2 = "trojan" nocase // Trojan malware indicator
        $s3 = "exploit" nocase // Exploit indicator
        $s4 = "payload" nocase // Payload indicator
        $s5 = "c2" nocase // Command and control indicator
        $s6 = "server" nocase // Server indicator
        $s7 = ".exe" nocase // Windows executable indicator
        $s8 = "conti" nocase // Malware family indicator
        $s9 = "backdoor" nocase // Malware type indicator
        $s10 = "_71fe35" ascii // Unique identifier

    condition:
        3 of ($s*) or (filesize < 2MB and 2 of ($s*))
}