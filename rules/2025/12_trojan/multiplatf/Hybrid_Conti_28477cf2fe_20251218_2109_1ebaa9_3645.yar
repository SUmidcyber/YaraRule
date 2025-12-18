rule Hybrid_Conti_28477cf2fe {
    meta:
        author = "UmidCyber AI Bot"
        date = "2025-12-18"
        description = "Hybrid detection for: Frogblight threatens you with a court case: a new Android banker targets Turkish"
        reference = "https://securelist.com/frogblight-banker/118440/"
        threat_level = 6
        source = "Securelist"
        note = "Hybrid rule (IOC + keywords)"
        confidence = "Medium"
        version = "3.0"

    strings:
        $kw1 = "article" // Article keyword
        $kw2 = "content" // Article keyword
        $kw3 = "descriptions" // Article keyword
        $kw4 = "frogblight" // Article keyword
        $kw5 = "threatens" // Article keyword
        $mal6 = "conti" // Malware name
        $mal7 = "users" // Malware name

    condition:
        any of ($mal*) or 2 of ($kw*)
}