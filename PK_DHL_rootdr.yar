rule PK_DHL_rootdr : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-03"
        comment = "Phishing Kit - DHL - 'Coded By Root_Dr'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "app"
        $spec_dir2 = "prevents"
        $spec_dir3 = "botActBan"
        $spec_file1 = "infoz.php"
        $spec_file2 = "ar.php"
        $spec_file3 = "particles copy.js"
        $spec_file4 = "dhl-logo.svg"
        $spec_file5 = "hacker-25929.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
