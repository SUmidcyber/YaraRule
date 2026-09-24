rule Loader_Group_Policy_8d14b0 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-09-24"
        description = "Advanced detection rule for loader: Group Policy hijacked: PAYLOAD ransomware weaponizes Active Directory "
        reference = "https://securelist.com/tr/payload-ransomware-via-group-policy/121335/"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1105, T1071, T1566, T1132, T1204"
        behaviors = "Registry Persistence, Scheduled Task, Service Installation, Startup Folder, AV/EDR Disabling"
        source = "Securelist"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "0108656A3E1ADE6CA4F21B084F5E1208"
        $hash2 = "0108656a3e1ade6ca4f21b084f5e1208"
        $hash3 = "BEA5E267F24D7DA59F6821BFFDBFF293"

        // Network Indicators
        $domain1 = "ScheduledTasks.xml"
        $domain2 = "payload.jpg"
        $domain3 = "THECOMPANY.local"
        $ip1 = "37.19.210.12"
        $ip2 = "146.70.117.239"

        // Behavioral Indicators
        $behavior1 = "PsExec"
        $behavior2 = "PowerShell logs, and operational channels   * A co"
        $behavior3 = "PowerShell, service control, and system changes. H"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Registry Persistence, Scheduled Task, Service Installation T1105, T1071, T1566
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            