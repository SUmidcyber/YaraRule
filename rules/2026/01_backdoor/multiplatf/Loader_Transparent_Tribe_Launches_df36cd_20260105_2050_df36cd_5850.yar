rule Loader_Transparent_Tribe_Launches_df36cd {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for loader: Transparent Tribe Launches New RAT Attacks Against Indian Government a"
        reference = "https://thehackernews.com/2026/01/transparent-tribe-launches-new-rat.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1082, T1115, T1059, T1547, T1566"
        behaviors = "Registry Persistence, Scheduled Task, Startup Folder, Code Signing Abuse, WMI Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "af41be456f6393a24771846328e8d7f2"
        $hash2 = "3a4f47c60edf1e00adb3ca60a7643062657fe2c6dd85ace9dfd8fdec47078d4e"
        $hash3 = "dc297aded70b0692ad0a24509e7bbec210bc0a1c7a105e99e1a8f76e3861ad34"

        // Network Indicators
        $domain1 = "rat.html"
        $domain2 = "based-transparent-tribe.html"
        $domain3 = "indian-government-with.html"

        // Behavioral Indicators
        $behavior1 = "cmd.exe"
        $behavior2 = "cmd.exe"
        $behavior3 = "PowerShell   * FL_SH1, to close all shells   * C9E"

        // File Artifacts
        $file1 = "cmd.exe"
        $file2 = "pdf.dll"
        $file3 = "cmd.exe"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Registry Persistence, Scheduled Task, Startup Folder T1082, T1115, T1059
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            