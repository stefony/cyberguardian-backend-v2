/*
    CyberGuardian AI - Trojan Detection Rules
    Trojan-specific signatures
*/

rule Remote_Access_Trojan
{
    meta:
        description = "Detects Remote Access Trojan (RAT) behavior"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "trojan"
    
    strings:
        $rat1 = "RemoteDesktop" nocase
        $rat2 = "VNC" nocase
        $rat3 = "TeamViewer" nocase
        $rat4 = "AnyDesk" nocase
        $screen = "screenshot" nocase
        $keylog = "keylog" nocase
        $webcam = "webcam" nocase
        $remote = "remote control" nocase
    
    condition:
        3 of them
}

rule Banking_Trojan
{
    meta:
        description = "Detects banking trojan patterns"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "trojan"
    
    strings:
        $bank1 = "bank" nocase
        $bank2 = "credit card" nocase
        $bank3 = "account number" nocase
        $form = "form grabber" nocase
        $inject = "browser inject" nocase
        $hook1 = "SetWindowsHookEx" ascii
        $hook2 = "GetMessageA" ascii
    
    condition:
        2 of ($bank*) and (any of ($form, $inject, $hook*))
}

rule Backdoor_Trojan
{
    meta:
        description = "Detects backdoor trojan behavior"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "trojan"
    
    strings:
        $backdoor = "backdoor" nocase
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell.exe" nocase
        $shell = "reverse_shell" nocase
        $bind = "bind_shell" nocase
        $socket = "socket" nocase
        $listen = "listen" nocase
    
    condition:
        $backdoor or ($shell or $bind) or (any of ($cmd*) and 2 of ($socket, $listen))
}

rule Trojan_Downloader
{
    meta:
        description = "Detects trojan downloader behavior"
        author = "CyberGuardian AI"
        severity = "high"
        category = "trojan"
    
    strings:
        $download1 = "URLDownloadToFile" ascii
        $download2 = "InternetOpenUrl" ascii
        $download3 = "WinHttpOpen" ascii
        $exec1 = "ShellExecute" ascii
        $exec2 = "CreateProcess" ascii
        $temp = "\\AppData\\Local\\Temp\\" ascii nocase
    
    condition:
        any of ($download*) and any of ($exec*) and $temp
}

rule Trojan_Dropper
{
    meta:
        description = "Detects trojan dropper behavior"
        author = "CyberGuardian AI"
        severity = "high"
        category = "trojan"
    
    strings:
        $drop1 = "CreateFile" ascii
        $drop2 = "WriteFile" ascii
        $resource = "FindResource" ascii
        $load = "LoadResource" ascii
        $startup = "\\Start Menu\\Programs\\Startup\\" nocase
    
    condition:
        ($drop1 and $drop2) and ($resource or $load) and $startup
}

rule Spyware_Trojan
{
    meta:
        description = "Detects spyware trojan behavior"
        author = "CyberGuardian AI"
        severity = "high"
        category = "trojan"
    
    strings:
        $spy1 = "spy" nocase
        $key1 = "GetAsyncKeyState" ascii
        $key2 = "GetKeyState" ascii
        $clip = "GetClipboardData" ascii
        $screen = "BitBlt" ascii
        $window = "GetForegroundWindow" ascii
    
    condition:
        $spy1 or (any of ($key*) and ($clip or $screen or $window))
}

rule Trojan_Persistence
{
    meta:
        description = "Detects trojan persistence mechanisms"
        author = "CyberGuardian AI"
        severity = "high"
        category = "trojan"
    
    strings:
        $reg1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $reg2 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
        $sched = "schtasks" nocase
        $service = "CreateService" ascii
        $startup = "Startup" nocase
    
    condition:
        2 of them
}

rule Zeus_Trojan_Signature
{
    meta:
        description = "Zeus/Zbot banking trojan signature"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "trojan"
        family = "Zeus"
    
    strings:
        $str1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\{" ascii
        $str2 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii
        $str3 = "bcdedit.exe /set {default} recoveryenabled no" ascii
        $mutex = "Local\\{" ascii
    
    condition:
        2 of them
}