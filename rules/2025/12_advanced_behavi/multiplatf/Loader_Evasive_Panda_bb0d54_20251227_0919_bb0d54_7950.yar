rule Loader_Evasive_Panda_bb0d54 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2025-12-27"
        description = "Advanced detection rule for loader: Evasive Panda APT poisons DNS requests to deliver MgBot"
        reference = "https://securelist.com/evasive-panda-apt/118576/"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        mitre_techniques = "T1105, T1566, T1071, T1547, T1132"
        behaviors = "N/A"
        source = "Securelist"
        version = "4.0"
        category = "Advanced_Behavioral"
        detection_type = "Behavioral & IOC"
    strings:

        // File Hashes
        $hash1 = "1c36452c2dad8da95d460bee3bea365e"
        $hash2 = "c340195696d13642ecf20fbe75461bed"
        $hash3 = "c340195696d13642ecf20fbe75461bed"

        // Network Indicators
        $domain1 = "ovztb0wktdmakeszwh2eha.exe"
        $domain2 = "ovztb0wktdmakeszwh2eha.exe"
        $domain3 = "qiyiservice.exe"
        $ip1 = "7.0.18.0"
        $ip2 = "60.28.124.21"

        // Behavioral Indicators
        $behavior1 = "RtlGetVersion"
        $behavior2 = "explorer.exe"
        $behavior3 = "svchost.exe"

        // File Artifacts
        $file1 = "tp.exe"
        $file2 = "ext.exe"
        $file3 = "ext.exe"

        // Loader specific
        $download_execute1 = "URLDownloadToFile" wide
        $download_execute2 = "WinExec" wide
        $shellcode_loader = "VirtualAlloc" wide
        $process_hollowing = "NtUnmapViewOfSection" wide
        $stager1 = "stage" wide ascii
        $stager2 = "payload" wide ascii

        condition:
        // MITRE ATT&CK Techniques: T1105, T1566, T1071
            // Loader/dropper detection logic
            (
                ( $download_execute and $payload_fetch ) or
                ( $shellcode_loader and $process_hollowing ) or
                ( any of ($stager*) and $second_stage )
            ) and
            pe.is_pe and
            filesize < 5MB
            