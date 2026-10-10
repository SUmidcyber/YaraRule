rule Loader_Blinder_Tunnel_Campaign_767a54 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-10"
        description = "Detection for loader: Blinder Tunnel Campaign Targets Iraqi Infrastructure"
        reference = "https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/"
        threat_level = 9
        malware_type = "loader"
        confidence_score = 95
        source = "Unit 42"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "3fd810a3aa0039993393741b32287c367a9a5037a41e826906440887cdd3ed13"
        $hash2 = "f5ba1645694c62f527ed6ceda8c68a5c3dd92b4032439167e8e937e72803b4bd"
        $hash3 = "d3561bd4aad003dc3e08157b0891860bb496b80cd6e44901692e08ab1d4e8260"
        $hash4 = "f5b12772db6817f7a765a6fe7565fd3d4f87edc28e42fe3ec0244a372a410fc9"
        $hash5 = "7cc571aca6d8715d9aaad3d83e1bcd30467565d583db1dfe73697c5d00a1f875"

        // Domains
        $domain1 = "RuntimeBroker.exe.config" nocase
        $domain2 = "FlightManager.csproj" nocase

        // Files
        $file1 = "PowerShell.exe" nocase

        // Behavioral
        $behavior1 = "PsProxy" nocase
        $behavior2 = "explorer.exe" nocase
        $behavior3 = "PowerShell.exe" nocase

    condition:
        (2 of ($hash*, $domain*, $behavior*, $file*)) and filesize < 10MB
