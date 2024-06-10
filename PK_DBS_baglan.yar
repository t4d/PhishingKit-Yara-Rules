rule PK_DBS_baglan : DBS
{
    meta:
        description = "Phishing Kit impersonating DBS bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-03"
        comment = "Phishing Kit - DBS - using a 'baglan.php' file"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "wbot"
        $spec_file1 = "cikis.php"
        $spec_file2 = "baglan.php"
        $spec_file3 = "fonksiyon.php"
        $spec_file4 = "arkaplan.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
