rule PK_DHL_abberry : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-15"
        comment = "Phishing Kit - DHL - '+ Created BY Mr-Abberry in 2017 (skype:Anonymous) +'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "Logon2.php"
        $spec_file2 = "Secinfo.php"
        $spec_file3 = "tracking2.php"
        $spec_file4 = "dhl_logo.gif"
        $spec_file5 = "deliveryform.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
