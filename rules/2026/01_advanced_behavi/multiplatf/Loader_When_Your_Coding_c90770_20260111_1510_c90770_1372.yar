rule Loader_When_Your_Coding_c90770 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: When Your AI Coding Plugin Starts Picking Your Dependencies: Marketpla"
        reference = "https://www.sentinelone.com/blog/marketplace-skills-and-dependency-hijack-in-claude-code/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 85
        mitre_techniques = "T1573, T1105, T1204, T1071, T1547"
        behaviors = "N/A"
        source = "SentinelOne"
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
        // MITRE ATT&CK Techniques: T1573, T1105, T1204
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            