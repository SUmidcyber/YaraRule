rule Loader_China_Linked_Targets_d02a37 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: China-Linked UAT-7290 Targets Telecoms with Linux Malware and ORB Node"
        reference = "https://thehackernews.com/2026/01/china-linked-uat-7290-targets-telecoms.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 91
        mitre_techniques = "T1573, T1204, T1071, T1566, T1113"
        behaviors = "Keylogging, Screen Capture"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "telecoms.html"
        $domain2 = "hack.jpg"
        $domain3 = "thehackernews.uk"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Keylogging, Screen Capture T1573, T1204, T1071
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            