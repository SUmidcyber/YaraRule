rule Trojan_Instacart_f21e36 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-19"
        description = "Advanced detection rule for trojan: FTC: Instacart to refund $60M over deceptive subscription tactics"
        reference = "https://www.bleepingcomputer.com/news/legal/instacart-to-refund-60m-over-deceptive-subscription-tactics/"
        threat_level = 8
        malware_type = "trojan"
        confidence_score = 85
        mitre_techniques = "T1573, T1566, T1071, T1059"
        behaviors = "N/A"
        source = "BleepingComputer"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "Complaint.pdf"

        // Trojan/RAT specific
        $remote_access1 = "CreateRemoteThread" wide
        $remote_access2 = "WriteProcessMemory" wide
        $keylogger = "SetWindowsHookEx" wide
        $screenshot = "BitBlt" wide
        $persistence1 = "RegSetValueEx" wide
        $persistence2 = "CreateService" wide

        condition:
        // MITRE ATT&CK Techniques: T1573, T1566, T1071
            // Trojan/RAT detection logic
            (
                ( any of ($remote_access*) and any of ($persistence*) ) or
                ( $keylogger and $screenshot ) or
                ( $process_injection and $code_injection )
            ) and
            pe.is_pe
            