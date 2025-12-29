rule Loader_The_cb9c79 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-29"
        description = "Advanced detection rule for loader: The HoneyMyte APT evolves with a kernel-mode rootkit and a ToneShell b"
        reference = "https://securelist.com/honeymyte-kernel-mode-rootkit/118590/"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1105, T1204, T1082, T1059, T1060"
        behaviors = "Code Signing Abuse"
        source = "Securelist"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "36f121046192b7cac3e4bec491e8f1b5"
        $hash2 = "36f121046192b7cac3e4bec491e8f1b5"
        $hash3 = "fe091e41ba6450bcf6a61a2023fe6c83"

        // Network Indicators
        $domain1 = "honeymyte-kernel1.png"
        $domain2 = "ProjectConfiguration.sys"
        $domain3 = "ntoskrnl.exe"

        // Behavioral Indicators
        $behavior1 = "ZwQuerySystemInformation"
        $behavior2 = "SeLocalSystemSid"
        $behavior3 = "CmRegisterCallbackEx"
        $behavior4 = "PsSetCreateProcessNotifyRoutine"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse T1105, T1204, T1082
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            