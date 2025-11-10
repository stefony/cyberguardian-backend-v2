/*
    CyberGuardian AI - Custom Detection Rules
    User-defined and experimental rules
*/

rule Suspicious_File_Extension
{
    meta:
        description = "Detects files with suspicious double extensions"
        author = "CyberGuardian AI"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $ext1 = ".pdf.exe" nocase
        $ext2 = ".docx.exe" nocase
        $ext3 = ".jpg.exe" nocase
        $ext4 = ".txt.exe" nocase
        $ext5 = ".zip.exe" nocase
    
    condition:
        any of them
}

rule Suspicious_Script_Extension
{
    meta:
        description = "Detects potentially malicious script files"
        author = "CyberGuardian AI"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $ext1 = ".vbs" nocase
        $ext2 = ".js" nocase
        $ext3 = ".bat" nocase
        $ext4 = ".cmd" nocase
        $ext5 = ".ps1" nocase
        $download = "download" nocase
        $exec = "execute" nocase
    
    condition:
        any of ($ext*) and ($download or $exec)
}

rule Encoded_Content
{
    meta:
        description = "Detects base64 or other encoded content"
        author = "CyberGuardian AI"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $base64_1 = /[A-Za-z0-9+\/]{50,}={0,2}/ ascii
        $hex = /[0-9A-Fa-f]{100,}/ ascii
        $decode1 = "base64" nocase
        $decode2 = "decode" nocase
    
    condition:
        ($base64_1 or $hex) and any of ($decode*)
}

rule Suspicious_URL_Pattern
{
    meta:
        description = "Detects suspicious URL patterns"
        author = "CyberGuardian AI"
        severity = "medium"
        category = "suspicious"
    
    strings:
        $ip = /http[s]?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii
        $suspicious_tld1 = ".tk" nocase
        $suspicious_tld2 = ".ml" nocase
        $suspicious_tld3 = ".ga" nocase
        $suspicious_tld4 = ".cf" nocase
        $suspicious_tld5 = ".gq" nocase
    
    condition:
        $ip or any of ($suspicious_tld*)
}

rule Anti_VM_Detection
{
    meta:
        description = "Detects anti-VM and sandbox evasion techniques"
        author = "CyberGuardian AI"
        severity = "high"
        category = "evasion"
    
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "VBOX" nocase
        $vm4 = "QEMU" nocase
        $sandbox1 = "sandbox" nocase
        $sandbox2 = "SbieDll.dll" nocase
        $check1 = "HKEY_LOCAL_MACHINE\\HARDWARE\\Description\\System\\SystemBiosVersion" ascii
    
    condition:
        2 of them
}

rule Debugger_Detection
{
    meta:
        description = "Detects anti-debugging techniques"
        author = "CyberGuardian AI"
        severity = "medium"
        category = "evasion"
    
    strings:
        $api1 = "IsDebuggerPresent" ascii
        $api2 = "CheckRemoteDebuggerPresent" ascii
        $api3 = "NtQueryInformationProcess" ascii
        $api4 = "OutputDebugString" ascii
    
    condition:
        2 of them
}

rule Credential_Stealer
{
    meta:
        description = "Detects credential stealing behavior"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "stealer"
    
    strings:
        $cred1 = "password" nocase
        $cred2 = "credential" nocase
        $cred3 = "SAM" nocase
        $cred4 = "LSASS" nocase
        $browser1 = "Chrome\\User Data" nocase
        $browser2 = "Firefox\\Profiles" nocase
        $wallet = "wallet.dat" nocase
    
    condition:
        2 of ($cred*) or any of ($browser*) or $wallet
}

rule Cryptocurrency_Miner
{
    meta:
        description = "Detects cryptocurrency mining malware"
        author = "CyberGuardian AI"
        severity = "high"
        category = "miner"
    
    strings:
        $pool1 = "pool" nocase
        $pool2 = "stratum" nocase
        $algo1 = "cryptonight" nocase
        $algo2 = "ethash" nocase
        $miner1 = "xmrig" nocase
        $miner2 = "claymore" nocase
        $wallet = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
    
    condition:
        ($pool1 or $pool2) and (any of ($algo*) or any of ($miner*)) or $wallet
}