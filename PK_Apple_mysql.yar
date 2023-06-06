rule PK_Apple_mysql : Apple
{
    meta:
        description = "Phishing Kit impersonating Apple"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-04"
        comment = "Phishing Kit - Apple - using mysql db to store collected data"

    strings:
        $zip_file = { 50 4b 03 04 }

        $spec_file1 = "iphone.php"
        $spec_file2 = "redirect.php"
        $spec_file3 = "dbconfig.php"
        $spec_file4 = "short.class.php"
        $spec_file5 = "iphone.sql"
        $spec_file6 = "style.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
