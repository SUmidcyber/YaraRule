rule Critical_React2shell_Flaw_a67d1145 {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Detects Conti: Critical React2Shell flaw exploited in ransomware attacks"
        reference = "https://www.bleepingcomputer.com/news/security/critical-react2shell-flaw-exploited-in-ransomware-attacks/"
        threat_level = 9
        malware_family = "Conti"
        platform = "MultiPlatform"
        target_os = "Windows"
        language = "PowerShell"
        capabilities = "malware_detection"
        source = "BleepingComputer"
        ioc_count = 18
        version = "3.0"
        generated_from = "EliteYaraGenerator"

    strings:
        $domain1 = "www.bleepingcomputer.com"
        $domain2 = "www.bleepingcomputer.com"
        $domain3 = "www.bleepingcomputer.com"
        $file4 = "Next.js"

    condition:
        any of ($domain*)
}