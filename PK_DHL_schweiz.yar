rule PK_DHL_schweiz : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-11"
        comment = "Phishing Kit - DHL - target 'Schweiz'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "info_files"
        $spec_dir2 = "sms2_files"
        $spec_dir3 = "loding_files"
        $spec_file1 = "info.php"
        $spec_file2 = "indexx.html"
        $spec_file3 = "54azd1052.php"
        $spec_file4 = "c125ac8554444.php"
        $spec_file5 = "dhl-logo-png-699118.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
