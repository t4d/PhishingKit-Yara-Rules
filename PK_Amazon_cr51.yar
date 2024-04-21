rule PK_Amazon_cr51 : Amazon
{
    meta:
        description = "Phishing Kit impersonating Amazon"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-08"
        comment = "Phishing Kit - Amazon - 'CR51 Network'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "panel"
        $spec_dir1 = "_hayo"
        $spec_dir2 = "Backlist"
        $spec_file1 = "cr51.htaccess"
        $spec_file2 = "cr51.install.script.js"
        $spec_file3 = "setpanel.ini"
        $spec_file4 = "log_3dsecure.txt"
        $spec_file5 = "atas.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
