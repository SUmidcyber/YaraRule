rule Trojan_Criminal_Palo_Alto_ec83e5 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for trojan: Criminal IP and Palo Alto Networks Cortex XSOAR integrate to bring AI-"
        reference = "https://www.bleepingcomputer.com/news/security/criminal-ip-and-palo-alto-networks-cortex-xsoar-integrate-to-bring-ai-driven-exposure-intelligence-to-automated-incident-response/"
        threat_level = 9
        malware_type = "trojan"
        confidence_score = 91
        mitre_techniques = "T1204, T1113, T1071, T1573"
        behaviors = "Code Signing Abuse, Screen Capture"
        source = "BleepingComputer"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "criminalip.io"

        // Trojan/RAT specific
        $remote_access1 = "CreateRemoteThread" wide
        $remote_access2 = "WriteProcessMemory" wide
        $keylogger = "SetWindowsHookEx" wide
        $screenshot = "BitBlt" wide
        $persistence1 = "RegSetValueEx" wide
        $persistence2 = "CreateService" wide

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse, Screen Capture T1204, T1113, T1071
            // Trojan/RAT detection logic
            (
                ( any of ($remote_access*) and any of ($persistence*) ) or
                ( $keylogger and $screenshot ) or
                ( $process_injection and $code_injection )
            ) and
            pe.is_pe
            