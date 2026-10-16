rule Loader_Unit_Uncovers_Stealthy_60ee95 {
    meta:
        author = "UmidCyber Elite AI"
        date = "2026-10-16"
        description = "Detection for loader: Unit 42 Uncovers PEERSTITCH, a Stealthy FortiGate Implant"
        reference = "https://unit42.paloaltonetworks.com/fortimanager-cve-2024-47575-peerstitch-malware/"
        threat_level = 8
        malware_type = "loader"
        confidence_score = 88
        source = "Unit 42"
        version = "5.0"
    strings:

        // Hashes
        $hash1 = "829b1cd270b30565739a478441833f49f10a49bd06f0d18cc96c8ae4a0431f11"
        $hash2 = "9c4c4436ff5cdf0d6d68f5108031cbf3708a095cde4ef8c09316af7a7110437e"
        $hash3 = "fc1b10c58057ef9f1f9a1e2a3d4a1c89f43b0ead451398c70ed7a6e0312b36ee"
        $hash4 = "b7ae166fd49a7ecfe6322a80b8aa56d6aa0825d8f5d106dab2e4fb7d14ce15a8"
        $hash5 = "bd064244dad748cf2a44074bee56f5bfab4a2b18ee944b75d1b3febd4c1fe02a"

        // Files
        $file1 = "pM.js" nocase

    condition:
        (( any of ($hash*) and any of ($file*) )) and filesize < 10MB
