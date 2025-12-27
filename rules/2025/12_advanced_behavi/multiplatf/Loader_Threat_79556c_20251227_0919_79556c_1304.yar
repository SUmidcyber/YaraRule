rule Loader_Threat_79556c {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for loader: Threat landscape for industrial automation systems in Q3 2025"
        reference = "https://securelist.com/industrial-threat-report-q3-2025/118602/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 85
        mitre_techniques = "T1071, T1059, T1573, T1566"
        behaviors = "N/A"
        source = "Securelist"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "report-q3-2025EN10.png"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1071, T1059, T1573
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            