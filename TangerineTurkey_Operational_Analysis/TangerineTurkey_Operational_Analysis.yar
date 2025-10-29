rule TangerineTurkey_Operational_Analysis {
    meta:
        description = "Tangerine Turkey kampanyası, USB'den başlayan, LOLBin'lerden yararlanan ve savunmaları atlatan katmanlı bir saldırı stratejisi sergiliyor. Birincil etkisi, sistem kaynaklarını çalarak finansal kazanç sağlamak olsa da, kullandığı teknikler sistemlerin istikrarsızlaşmasına veya başka kötü amaçlı yazılımların bulaşmasına zemin hazırlayabilir."
        author = "Umid Mammadov"
        date = "10/29/2025"
        threat_level = "High"
        writeup_me = "sibermerkez.com"
    
    strings:
        // Dosya Isimleri ve Yollari
        $dosya1 = "x817994.vbs" nocase 
        $dosya2 = "x966060.bat" nocase 
        $dosya3 = "x209791.dat" nocase 
        $dosya4 = "svculdr64.dat" nocase 
        $dosya5 = "x665422.dat" nocase 
        $dosya6 = "console_zero.exe" nocase 
        $dosya7 = "C:\\Windows \\System32" ascii 
        $dosya8 = "rootdir\\" nocase 

        // Hash Degerleri
        $hash1 = "93d74ed188756507c6480717330365cede4884e98aeb43b38d707ed0b98da7cc" // svculdr64.dat
        $hash2 = "4617cfd1e66aab547770f049abd937b46c4722ee33bbf97042aab77331aa6525" // printui.dll
        $hash3 = "4ffb3c0c7b38105183fb06d1084ab943c6e87f9644f783014684c5cb8db32e32" // console_zero.exe

        // Komut & Komut Satiri Indikatorleri
        $komut1 = "wscript.exe" wide 
        $komut2 = "printui.exe" wide 
        $komut3 = "sc create x665422" wide 
        $komut4 = "Add-MpPreference -ExclusionPath" wide 
        $komut5 = "schtasks /create /tn \"console_zero\"" wide 
        $komut6 = "rmdir /s /q \"C:\\Windows \"" wide 
        $komut7 = "timeout /t 14 && del" wide 

        // Registry Anahtarlari
        $registry1 = "HKLM\\SYSTEM\\CurrentControlSet\\services\\x665422\\Parameters" ascii 
        $registry2 = "ServiceDll" wide 

        // Script Patternleri
        $script1 = "CreateObject(\"WScript.Shell\").Run" nocase 
        $script2 = "cmd.exe /c" nocase 
        $script3 = "xcopy.*C:\\Windows \\System32" nocase 
        $script4 = "timeout.*rmdir" nocase 

        // Ag Indikatorleri
        $ag1 = "rootunv" nocase 
        $ag2 = "raw.githubusercontent.com" nocase

        // Servis & Process Iliskileri
        $servis1 = "svchost.exe -k DcomLaunch" wide 
        $servis2 = "x665422.dat" wide 

    condition:
        filesize < 10MB and (
            any of ($hash*) or
            // 3 dosya ismi + 2 komut kombinasyonu
            (3 of ($dosya*) and 2 of ($komut*)) or
            // 2 komut + registry + script kombinasyonu
            (2 of ($komut*) and 1 of ($registry*) and 1 of ($script*)) or
            ($dosya7 and 2 of ($komut*)) or // Sahte Windows yolu + komutlar
            ($dosya8 and 1 of ($dosya1) and 1 of ($dosya2)) or // USB yolu + VBS/BAT
            (1 of ($ag*) and 2 of ($dosya*)) or
            // Servis iliskileri
            ($servis1 and $servis2 and 1 of ($komut*))
        )
}