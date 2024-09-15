rule PK_DHL_blackforce : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-05"
        comment = "Phishing Kit - DHL - 'Black Force'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Panel"
        $spec_dir2 = "Config"
        $spec_dir3 = "fastCardLink"
        $spec_file1 = "pin.php"
        $spec_file2 = "infoz.php"
        $spec_file4 = "insert_badiban.php"
        $spec_file5 = "stats.ini"
        $spec_file6 = "dhl-logo.svg"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
