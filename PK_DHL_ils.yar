rule PK_DHL_ils : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-26"
        comment = "Phishing Kit - DHL - use ILS currency"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "store"
        $spec_dir2 = "config"
        $spec_file1 = "load.php"
        $spec_file2 = "action4.php"
        $spec_file3 = "tg.php"
        $spec_file4 = "bus.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
