rule Loader_Cracked_Software_Videos_fb7893 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-20"
        description = "Advanced detection rule for loader: Cracked Software and YouTube Videos Spread CountLoader and GachiLoader"
        reference = "https://thehackernews.com/2025/12/cracked-software-and-youtube-videos.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1059, T1071, T1082, T1105, T1573"
        behaviors = "Scheduled Task, UAC Bypass, WMI Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "malware.jpg"
        $domain2 = "expose-svg-and-purerat.html"
        $domain3 = "ransomware.html"

        // Behavioral Indicators
        $behavior1 = "cmd.exe"
        $behavior2 = "rundll32.exe"
        $behavior3 = "PowerShell. The complete list of supported feature"
        $behavior4 = "PowerShell payload in memory"

        // File Artifacts
        $file1 = "cmd.exe"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Scheduled Task, UAC Bypass, WMI Abuse T1059, T1071, T1082
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            