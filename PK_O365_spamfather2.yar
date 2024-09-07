rule PK_O365_spamfather2: Office365
{
    meta:
        description = "Phishing Kit impersonating Office 365"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-02"
        comment = "Phishing Kit - Office 365 - spamfather"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_dir2 = "images"
        $spec_file1 = "appverify.php"
        $spec_file3 = "check.php"
        $spec_file4 = "phoneotp.php"
        $spec_file5 = "microsoft_logo.svg"
        $spec_file6 = "mg.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
