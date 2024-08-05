rule PK_WhatsApp_arpantek : WhatsApp
{
    meta:
        description = "Phishing Kit impersonating WhatsApp"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-05"
        comment = "Phishing Kit - WhatsApp - 'SCRIPT BY ARPANTEK'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "settingkiki"
        $spec_dir2 = "system"
        $spec_dir3 = "v4"
        // specific file found in PhishingKit
        $spec_file = "setting.php"
        $spec_file1 = "apiii.php"
        $spec_file2 = "ganti.php"
        $spec_file3 = "get_callingcode.php"
        $spec_file4 = "SetyawanXD.css"
        $spec_file5 = "fb-bawah.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
       $local_file and 
       all of ($spec_dir*) and 
       all of ($spec_file*)
}
