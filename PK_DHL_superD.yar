rule PK_DHL_superD : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-07"
        comment = "Phishing Kit - DHL - '//** Scama Version Super D panel - 12-11-2020'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "panel"
        $spec_dir2 = "system"
        $spec_file1 = "info.php"
        $spec_file2 = "portail.php"
        $spec_file3 = "setting.php"
        $spec_file4 = "verification2.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
