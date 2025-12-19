rule Loader_Cloud_Atlas_a5dcd3 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-19"
        description = "Advanced detection rule for loader: Cloud Atlas activity in the first half of 2025: what changed"
        reference = "https://securelist.com/cloud-atlas-h1-2025-campaign/118517/"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1204, T1071, T1566, T1573, T1132"
        behaviors = "Scheduled Task, Code Signing Abuse"
        source = "Securelist"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "0D309C25A835BAF3B0C392AC87504D9E"
        $hash2 = "0d309c25a835baf3b0c392ac87504d9e"
        $hash3 = "D34AAEB811787B52EC45122EC10AEB08"

        // Network Indicators
        $domain1 = "MicrosoftEdgeUpdate.vbs"
        $domain2 = "MicrosoftEdgeUpdate.vbs"
        $domain3 = "MicrosoftEdgeUpdate.vbs"

        // Behavioral Indicators
        $behavior1 = "wscript.exe"
        $behavior2 = "wscript.exe"
        $behavior3 = "cmd.exe"
        $behavior4 = "PowerShell_v1.0_powershell.exe\"::\"WindowPosition\":"
        $behavior5 = "PowerShell_v1.0_powershell.exe\"::\"WindowPosition\":"

        // File Artifacts
        $file1 = "cmd.exe"
        $file2 = "cmd.exe"
        $file3 = "vlc.exe"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Scheduled Task, Code Signing Abuse T1204, T1071, T1566
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            