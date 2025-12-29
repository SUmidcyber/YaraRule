rule Loader_December_Threat_Intelligence_190353 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-29"
        description = "Advanced detection rule for loader: 29th December – Threat Intelligence Report"
        reference = "https://research.checkpoint.com/2025/29th-december-threat-intelligence-report/"
        threat_level = 7
        malware_type = "loader"
        confidence_score = 75
        mitre_techniques = "T1573, T1071"
        behaviors = "N/A"
        source = "Check Point Research"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1573, T1071
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            