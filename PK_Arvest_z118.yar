rule PK_Arvest_z118 : Arvest
{
    meta:
        description = "Phishing Kit impersonating Arvest Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-06"
        comment = "Phishing Kit - Arvest - using 'Z118_' variable names"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "grabber"
        $spec_dir2 = "functions"

        $spec_file1 = "email_access.php"
        $spec_file2 = "get_browser.php"
        $spec_file3 = "Dila_DZ.php"
        $spec_file4 = "get_ip.php"
        $spec_file5 = "arvest-logo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
