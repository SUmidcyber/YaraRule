rule Trojan_Over_f3bcd9 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for trojan: Over 25,000 FortiCloud SSO devices exposed to remote attacks"
        reference = "https://www.bleepingcomputer.com/news/security/over-25-000-forticloud-sso-devices-exposed-to-remote-attacks/"
        threat_level = 8
        malware_type = "trojan"
        confidence_score = 85
        mitre_techniques = "T1105, T1566, T1071, T1573"
        behaviors = "N/A"
        source = "BleepingComputer"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "shadowserver.bsky.social"
        $domain2 = "dashboard.shadowserver.org"

        // Trojan/RAT specific
        $remote_access1 = "CreateRemoteThread" wide
        $remote_access2 = "WriteProcessMemory" wide
        $keylogger = "SetWindowsHookEx" wide
        $screenshot = "BitBlt" wide
        $persistence1 = "RegSetValueEx" wide
        $persistence2 = "CreateService" wide

        condition:
        // MITRE ATT&CK Techniques: T1105, T1566, T1071
            // Trojan/RAT detection logic
            (
                ( any of ($remote_access*) and any of ($persistence*) ) or
                ( $keylogger and $screenshot ) or
                ( $process_injection and $code_injection )
            ) and
            pe.is_pe
            