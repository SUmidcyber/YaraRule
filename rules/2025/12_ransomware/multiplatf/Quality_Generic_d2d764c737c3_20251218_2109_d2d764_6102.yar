rule Quality_Generic_d2d764c737c3 {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "High-quality generic detection: US seizes E-Note crypto exchange for laundering ransomware payments"
        reference = "https://www.bleepingcomputer.com/news/security/us-seizes-e-note-crypto-exchange-for-laundering-ransomware-payments/"
        threat_level = 5
        source = "BleepingComputer"
        note = "Quality generic rule with advanced indicators"
        confidence = "Medium"
        version = "3.0"

    strings:
        $kw1 = "article" nocase // Extracted from article
        $kw2 = "content" nocase // Extracted from article
        $kw3 = "seizes" nocase // Extracted from article
        $kw4 = "crypto" nocase // Extracted from article
        $kw5 = "exchange" nocase // Extracted from article
        $kw6 = "laundering" nocase // Extracted from article
        $kw7 = "ransomware" nocase // Extracted from article
        $kw8 = "payments" nocase // Extracted from article
        $adv1 = "GetProcAddress" nocase // Windows API call
        $adv2 = "LoadLibrary" nocase // DLL loading
        $adv3 = "VirtualAlloc" nocase // Memory allocation
        $adv4 = "CreateRemoteThread" nocase // Process injection
        $adv5 = "reg add" nocase // Registry modification
        $adv6 = "powershell" nocase // PowerShell execution
        $adv7 = "cmd.exe" nocase // Command prompt
        $adv8 = "schtasks" nocase // Scheduled task

    condition:
        (3 of ($kw*) and 1 of ($adv*)) or (4 of ($adv*))
}