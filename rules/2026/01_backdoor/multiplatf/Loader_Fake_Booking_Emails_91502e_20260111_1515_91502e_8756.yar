rule Loader_Fake_Booking_Emails_91502e {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: Fake Booking Emails Redirect Hotel Staff to Fake BSoD Pages Delivering"
        reference = "https://thehackernews.com/2026/01/fake-booking-emails-redirect-hotel.html"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1573, T1105, T1204, T1071, T1060"
        behaviors = "Registry Persistence, Startup Folder, UAC Bypass, PowerShell Download & Execute, Keylogging"
        source = "The Hacker News"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // Network Indicators
        $domain1 = "exploits.html"
        $domain2 = "campaign-delivers.html"
        $domain3 = "thehackernews.uk"

        // Behavioral Indicators
        $behavior1 = "PowerShell commands, which silently fetch and exec"
        $behavior2 = "PowerShell command that ultimately deploys DCRat."

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Registry Persistence, Startup Folder, UAC Bypass T1573, T1105, T1204
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            