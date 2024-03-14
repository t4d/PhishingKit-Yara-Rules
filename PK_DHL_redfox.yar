rule PK_DHL_redfox : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-11-10"
        comment = "Phishing Kit - DHL - 'By:Red Fox'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "system"
        $spec_dir2 = "results"
        $spec_dir3 = "languages"
        $spec_file1 = "detect.php"
        $spec_file2 = "api.php"
        $spec_file3 = "verification2.php"
        $spec_file4 = "chunk-vendors.524d9220.js"
        $spec_file5 = "DHL_logo_rgb.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
