rule PK_DHL_intern : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-23"
        comment = "Phishing Kit - DHL - '[ INTERN. - DHL OTP - 1  ]'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "store"
        $spec_dir2 = "lang"
        $spec_dir3 = "config"
        $spec_file1 = "action4.php"
        $spec_file2 = "conf.php"
        $spec_file4 = "cur.php"
        $spec_file5 = "app.css"
        $spec_file6 = "OIP.jfif"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
