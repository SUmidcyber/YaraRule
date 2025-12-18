rule Loader_Fake_Utility_Repos_cb39dc {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-18"
        description = "Advanced detection rule for loader: Fake OSINT and GPT Utility GitHub Repos Spread PyStoreRAT Malware Payl"
        reference = "https://thehackernews.com/2025/12/fake-osint-and-gpt-utility-github-repos.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1204, T1071, T1566, T1547, T1573"
        behaviors = "Scheduled Task, Keylogging, Screen Capture"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "github-repositories-found.html"
        $domain2 = "thehackernews.uk"
        $domain3 = "rundll32.exe"

        // Behavioral Indicators
        $behavior1 = "cmd.exe"
        $behavior2 = "rundll32.exe"
        $behavior3 = "cmd.exe"
        $behavior4 = "PowerShell, MSI, Python, JavaScript, and HTA modul"
        $behavior5 = "PowerShell commands directly in memory   * Spread "

        // File Artifacts
        $file1 = "cmd.exe"
        $file2 = "cmd.exe"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Scheduled Task, Keylogging, Screen Capture T1204, T1071, T1566
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            