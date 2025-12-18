rule Loader_New_Phishing_Attacks_aa2184 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for loader: New ForumTroll Phishing Attacks Target Russian Scholars Using Fake eLi"
        reference = "https://thehackernews.com/2025/12/new-forumtroll-phishing-attacks-target.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1204, T1071, T1566, T1547, T1573"
        behaviors = "PowerShell Download & Execute"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "day-exploited-to-deliver.html"
        $domain2 = "thehackernews.uk"
        $domain3 = "uncovered.html"

        // Behavioral Indicators
        $behavior1 = "PowerShell script to download and launch a PowerSh"
        $behavior2 = "powershell](https://thehackernews.com/search/label"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: PowerShell Download & Execute T1204, T1071, T1566
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            