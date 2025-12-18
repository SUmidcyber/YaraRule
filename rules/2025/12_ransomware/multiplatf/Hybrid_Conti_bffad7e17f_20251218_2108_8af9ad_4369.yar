rule Hybrid_Conti_bffad7e17f {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Hybrid detection for: LLMs & Ransomware | An Operational Accelerator, Not a Revolution"
        reference = "https://www.sentinelone.com/labs/llms-ransomware-an-operational-accelerator-not-a-revolution/"
        threat_level = 6
        source = "SentinelLabs - We are hunters, reversers, exploit developers, and tinkerers shedding light on the world of malware, exploits, APTs, and cybercrime across all platforms."
        note = "Hybrid rule (IOC + keywords)"
        confidence = "Medium"
        version = "3.0"

    strings:
        $kw1 = "article" // Article keyword
        $kw2 = "content" // Article keyword
        $kw3 = "intelligence" // Article keyword
        $kw4 = "ransomware" // Article keyword
        $kw5 = "operational" // Article keyword
        $mal6 = "conti" // Malware name
        $mal7 = "lockbit" // Malware name

    condition:
        any of ($mal*) or 2 of ($kw*)
}