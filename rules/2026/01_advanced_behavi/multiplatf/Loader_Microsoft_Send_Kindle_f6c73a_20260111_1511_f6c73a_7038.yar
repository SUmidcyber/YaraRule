rule Loader_Microsoft_Send_Kindle_f6c73a {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: Microsoft is retiring 'Send to Kindle' in Word"
        reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-is-retiring-send-to-kindle-in-word/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        mitre_techniques = "T1573, T1105, T1204, T1071, T1566"
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
        // Behaviors: WMI Abuse T1573, T1105, T1204
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            