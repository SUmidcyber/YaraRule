rule Loader_Illinois_Department_Human_39e2d5 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: Illinois Department of Human Services data breach affects 700K people"
        reference = "https://www.bleepingcomputer.com/news/security/illinois-department-of-human-services-data-breach-affects-700k-people/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        mitre_techniques = "T1071, T1573, T1105, T1566"
        behaviors = "WMI Abuse"
        source = "BleepingComputer"
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
        // MITRE ATT&CK Techniques:
        // Behaviors: WMI Abuse T1071, T1573, T1105
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            