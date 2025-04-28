rule PK_Schwab_z118 : Schwab
{
    meta:
        description = "Phishing Kit impersonating Schwab.com"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-27"
        comment = "Phishing Kit - Schwab.com - '$Z118_EMAIL'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "functions"
        $spec_dir2 = "grabber"
        $spec_file1 = "re_onetime.php"
        $spec_file2 = "get_browser.php"
        $spec_file3 = "userlogin.php"
        $spec_file4 = "schwab-secondary.css"
        $spec_file5 = "Schwab-Icon-Font.18dd8556f4400c8bbf55.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
