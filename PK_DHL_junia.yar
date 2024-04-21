rule PK_DHL_junia : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - DHL - 'Author : Junia'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ab"
        $spec_dir2 = "php"
        $spec_dir3 = "languages"
        $spec_file1 = "details.php"
        $spec_file2 = "saba9m.JPG"
        $spec_file3 = "loading6.php"
        $spec_file4 = "submit.js"
        $spec_file5 = "pin.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
