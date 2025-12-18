rule Loader_China_Linked_Ink_687772 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for loader: China-Linked Ink Dragon Hacks Governments Using ShadowPad and FINALDRA"
        reference = "https://thehackernews.com/2025/12/china-linked-ink-dragon-hacks.html"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        mitre_techniques = "T1204, T1071, T1566, T1547, T1573"
        behaviors = "Scheduled Task"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "microsoft.html"
        $domain2 = "microsoft.html"
        $domain3 = "microsoft.html"

        // File Artifacts
        $file1 = "cdb.exe"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Scheduled Task T1204, T1071, T1566
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            