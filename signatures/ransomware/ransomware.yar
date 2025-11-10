/*
    CyberGuardian AI - Ransomware Detection Rules
    Ransomware-specific signatures
*/

rule Ransomware_Extension_Change
{
    meta:
        description = "Detects ransomware file extension patterns"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $ext1 = ".locked" ascii
        $ext2 = ".encrypted" ascii
        $ext3 = ".crypt" ascii
        $ext4 = ".crypto" ascii
        $ext5 = ".locky" ascii
        $ext6 = ".cerber" ascii
        $ext7 = ".wannacry" ascii
        $ext8 = ".petya" ascii
    
    condition:
        any of them
}

rule Ransomware_Ransom_Note
{
    meta:
        description = "Detects ransomware ransom note patterns"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $note1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $note2 = "All your files are encrypted" nocase
        $note3 = "pay the ransom" nocase
        $note4 = "decrypt your files" nocase
        $note5 = "Bitcoin" nocase
        $note6 = "BTC address" nocase
        $note7 = "decryption key" nocase
        $note8 = "ATTENTION!" nocase
        $note9 = "README" nocase
        $note10 = "HOW TO DECRYPT" nocase
    
    condition:
        3 of them
}

rule Ransomware_Crypto_APIs
{
    meta:
        description = "Detects ransomware encryption API usage"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "CryptDecrypt" ascii
        $crypt3 = "CryptGenKey" ascii
        $crypt4 = "CryptAcquireContext" ascii
        $aes = "AES" ascii
        $rsa = "RSA" ascii
        $delete = "vssadmin delete shadows" ascii nocase
    
    condition:
        uint16(0) == 0x5A4D and  // MZ header
        4 of them
}

rule WannaCry_Signature
{
    meta:
        description = "WannaCry ransomware signature"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "ransomware"
        family = "WannaCry"
    
    strings:
        $str1 = "tasksche.exe" ascii
        $str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $str3 = "msg/m_bulgarian.wnry" ascii
        $str4 = "WNcry@2ol7" ascii
        $str5 = ".wnry" ascii
    
    condition:
        3 of them
}

rule Petya_Signature
{
    meta:
        description = "Petya/NotPetya ransomware signature"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "ransomware"
        family = "Petya"
    
    strings:
        $str1 = "MBR has been replaced" ascii
        $str2 = "wowsmith123456@posteo.net" ascii
        $str3 = "Repairing file system" ascii
        $bootloader = { 33 C0 8E D8 8E C0 8E D0 BC 00 7C }
    
    condition:
        2 of them
}

rule Ransomware_Shadow_Copy_Delete
{
    meta:
        description = "Detects shadow copy deletion (common ransomware behavior)"
        author = "CyberGuardian AI"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $vss1 = "vssadmin delete shadows /all /quiet" nocase
        $vss2 = "wmic shadowcopy delete" nocase
        $vss3 = "bcdedit /set {default} recoveryenabled no" nocase
        $vss4 = "wbadmin delete catalog -quiet" nocase
    
    condition:
        any of them
}

rule Ransomware_Bitcoin_Wallet
{
    meta:
        description = "Detects Bitcoin wallet addresses (common in ransomware)"
        author = "CyberGuardian AI"
        severity = "high"
        category = "ransomware"
    
    strings:
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $pay = "payment" nocase
        $wallet = "wallet" nocase
    
    condition:
        $btc and ($pay or $wallet)
}