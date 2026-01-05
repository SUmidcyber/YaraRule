rule Loader_Covenant_Health_May_51c982 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for loader: Covenant Health says May data breach impacted nearly 478,000 patients"
        reference = "https://www.bleepingcomputer.com/news/security/covenant-health-says-may-data-breach-impacted-nearly-478-000-patients/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 80
        mitre_techniques = "T1573, T1071, T1105"
        behaviors = "N/A"
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
        // MITRE ATT&CK Techniques: T1573, T1071, T1105
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            