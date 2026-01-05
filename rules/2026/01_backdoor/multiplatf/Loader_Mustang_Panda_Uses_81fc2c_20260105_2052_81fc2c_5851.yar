rule Loader_Mustang_Panda_Uses_81fc2c {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-05"
        description = "Advanced detection rule for loader: Mustang Panda Uses Signed Kernel-Mode Rootkit to Load TONESHELL Backdo"
        reference = "https://thehackernews.com/2025/12/mustang-panda-uses-signed-kernel-driver.html"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        mitre_techniques = "T1059, T1547, T1071, T1204, T1105"
        behaviors = "Code Signing Abuse"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "thehackernews.uk"
        $domain2 = "ProjectConfiguration.sys"
        $domain3 = "WdFilter.sys"

        // Behavioral Indicators
        $behavior1 = "svchost.exe"
        $behavior2 = "svchost.exe"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse T1059, T1547, T1071
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            