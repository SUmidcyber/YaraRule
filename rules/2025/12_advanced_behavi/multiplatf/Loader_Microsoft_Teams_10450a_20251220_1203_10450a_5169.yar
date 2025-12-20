rule Loader_Microsoft_Teams_10450a {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for loader: Microsoft confirms Teams is down and messages are delayed"
        reference = "https://www.bleepingcomputer.com/news/microsoft/microsoft-confirms-teams-is-down-and-messages-are-delayed/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 83
        mitre_techniques = "T1566, T1071, T1573"
        behaviors = "Screen Capture"
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
        // Behaviors: Screen Capture T1566, T1071, T1573
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            