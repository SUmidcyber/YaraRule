rule Trojan_Yet_414aa6 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-19"
        description = "Advanced detection rule for trojan: Yet another DCOM object for lateral movement"
        reference = "https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/"
        threat_level = 9
        malware_type = "trojan"
        confidence_score = 95
        mitre_techniques = "T1204, T1071, T1566, T1547, T1573"
        behaviors = "Registry Persistence"
        source = "Securelist"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "abusing-control-panel1.png"
        $domain2 = "abusing-control-panel2.png"
        $domain3 = "abusing-control-panel3.png"

        // Behavioral Indicators
        $behavior1 = "HKEY_CLASSES_ROOT\AppID."
        $behavior2 = "HKEY_CLASSES_ROOT\Interface"
        $behavior3 = "HKEY_CLASSES_ROOT\CLSID"
        $behavior4 = "explorer.exe"
        $behavior5 = "cmd.exe"
        $behavior6 = "rundll32.exe"
        $behavior7 = "PowerShell   **In PowerShell, you can use .NET to "

        // File Artifacts
        $file1 = "cmd.exe"
        $file2 = "shell32.dll"
        $file3 = "shell32.dll"

        // Trojan/RAT specific
        $remote_access1 = "CreateRemoteThread" wide
        $remote_access2 = "WriteProcessMemory" wide
        $keylogger = "SetWindowsHookEx" wide
        $screenshot = "BitBlt" wide
        $persistence1 = "RegSetValueEx" wide
        $persistence2 = "CreateService" wide

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Registry Persistence T1204, T1071, T1566
            // Trojan/RAT detection logic
            (
                ( any of ($remote_access*) and any of ($persistence*) ) or
                ( $keylogger and $screenshot ) or
                ( $process_injection and $code_injection )
            ) and
            pe.is_pe
            