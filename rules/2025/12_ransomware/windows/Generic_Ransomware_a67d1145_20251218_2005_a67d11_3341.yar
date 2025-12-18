rule Generic_Ransomware_a67d1145 {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Detects Generic Ransomware: Critical React2Shell flaw exploited in ransomware attacks"
        reference = "https://www.bleepingcomputer.com/news/security/critical-react2shell-flaw-exploited-in-ransomware-attacks/"
        threat_level = 3
        malware_family = "Generic"
        platform = "Windows"
        target_os = "Windows"
        language = "Windows_Native_or_NET"
        capabilities = "file_encryption"
        source = "BleepingComputer"
        ioc_count = 7
        version = "2.0"
        generated_from = "MalwareAnalysisBlog"

    strings:
        $domain1 = "powershell.exe" // C2 domain
        $domain2 = "cmd.exe" // C2 domain
        $domain3 = "Next.js" // C2 domain
        $file4 = "powershell.exe" // Malware file
        $file5 = "cmd.exe" // Malware file
        $file6 = "Next.js" // Malware file
        $win1 = "VirtualAlloc" nocase // Windows API
        $win2 = "CreateRemoteThread" nocase // Windows API
        $win3 = "WriteProcessMemory" nocase // Windows API

    condition:
        any of ($domain*) or any of ($ip*) or any of ($file*)
}