rule PK_DHL_911 : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-07"
        comment = "Phishing Kit - DHL - 911"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ABRID"
        $spec_dir2 = "X911"
        $spec_file1 = "911.php"
        $spec_file2 = "TELEGRMAT.php"
        $spec_file3 = "Abilli.php"
        $spec_file4 = "dhl-logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
