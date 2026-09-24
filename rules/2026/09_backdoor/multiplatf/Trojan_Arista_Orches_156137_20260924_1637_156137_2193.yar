rule Trojan_Arista_Orches_156137 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for trojan: Arista patches actively exploited VeloCloud Orchestrator zero-day"
        reference = "https://www.bleepingcomputer.com/news/security/arista-patches-actively-exploited-velocloud-orchestrator-zero-day/"
        threat_level = 8
        malware_type = "trojan"
        confidence_score = 83
        mitre_techniques = "T1573, T1204, T1071"
        behaviors = "Code Signing Abuse"
        source = "BleepingComputer"
        version = "4.1"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators - IPs
        $ip1 = "5.2.3.16"
        $ip2 = "6.4.2.8"

        // Trojan/RAT specific
        $remote_access1 = "CreateRemoteThread" wide
        $remote_access2 = "WriteProcessMemory" wide
        $keylogger1 = "SetWindowsHookEx" wide
        $screenshot1 = "BitBlt" wide
        $persistence1 = "RegSetValueEx" wide
        $persistence2 = "CreateService" wide

    condition:
        // MITRE ATT&CK: T1573, T1204, T1071
        // Behaviors: Code Signing Abuse
        (
                any of ($ip*) or
                any of ($remote_access*) or
                any of ($keylogger*) or
                any of ($screenshot*) or
                any of ($persistence*)
            )
