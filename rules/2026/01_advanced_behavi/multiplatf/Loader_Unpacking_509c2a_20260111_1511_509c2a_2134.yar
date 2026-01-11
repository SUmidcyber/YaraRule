rule Loader_Unpacking_509c2a {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-01-11"
        description = "Advanced detection rule for loader: Unpacking the packer ‘pkr_mtsi’"
        reference = "https://www.reversinglabs.com/blog/unpacking-pkr_mtsi"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1573, T1105, T1140, T1204, T1071"
        behaviors = "Code Signing Abuse"
        source = "ReversingLabs Blog"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "1ebd3356f36780960a03354a8ded23410ebc7e79"

        // Network Indicators
        $domain1 = "refinery.vstack"
        $domain2 = "KERNEL32.dll"

        // Behavioral Indicators
        $behavior1 = "NtProtectVirtualMemory"
        $behavior2 = "ZwAllocateVirtualMemory"
        $behavior3 = "import resolutions because it is not being loaded "

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques:
        // Behaviors: Code Signing Abuse T1573, T1105, T1140
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            