rule MultiPlatform_Trojan_NuGet_2025
{
    meta:
        author = "UmidCyber AI YARA Generator"
        date = "2025-12-18"
        description = "Detects NuGet malware, a multi-platform Trojan targeting VS Code extensions, npm, and PyPI packages. It often poses as a PNG file and can leverage PowerShell Gallery for attacks, aiming for crypto and OAuth token theft."
        reference = "https://www.reversinglabs.com/blog/nuget-malware-crypto-oauth-tokens"
        threat_level = 5
        malware_family = "NuGet"
        platform = "MultiPlatform"
        source = "