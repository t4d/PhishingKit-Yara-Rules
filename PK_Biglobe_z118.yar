rule PK_Biglobe_z118 : Biglobe
{
    meta:
        description = "Phishing Kit impersonating BIGLOBE (JP)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-05-15"
        comment = "Phishing Kit - BIGLOBE - '$Z118_EMAIL'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "grabber"
        $spec_dir2 = "Antibot"      
        $spec_file1 = "config.php"
        $spec_file2 = "userlogin.php"
        $spec_file3 = "btn_auid_30_240.png"
        $spec_file4 = "session_relogin.html"
        $spec_file5 = "logo_only_02A_200x71.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
