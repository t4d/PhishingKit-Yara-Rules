rule PK_DHL_x911 : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-25"
        comment = "Phishing Kit - DHL - 'by https://t.me/X911_tools'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Appearance"
        $spec_dir2 = "Assistant"
        $spec_dir3 = "Variablex"
        $spec_file1 = "XTelegram.php"
        $spec_file2 = "dynamo.php"
        $spec_file3 = "Loa.php"
        $spec_file4 = "Caralbab.php"
        $spec_file5 = "dhl-logo.svg"
        
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
