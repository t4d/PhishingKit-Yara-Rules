rule PK_DHL_azarox : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-27"
        comment = "Phishing Kit - DHL - 'Azar_ox'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "anti__boot"
        $spec_dir2 = "all_mixing"
        $spec_file1 = "loading_end.php"
        $spec_file2 = "sms_err.php"
        $spec_file3 = "spy.php"
        $spec_file4 = "telegram.php"
        $spec_file5 = "dhl-logo.svg"
        $spec_file6 = "camion.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
