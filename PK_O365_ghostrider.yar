rule PK_O365_ghostrider: Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-12-26"
        comment = "Phishing Kit - Office 365 - Ghost Rider"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "source"
        $spec_file1 = "cok.php"
        $spec_file3 = "Login.php"
        $spec_file4 = "Email.php"
        $spec_file5 = "data.php"
        $spec_file6 = "wrongpass.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
