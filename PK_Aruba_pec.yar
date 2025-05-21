rule PK_Aruba_pec : Aruba
{
    meta:
        description = "Phishing Kit impersonating Aruba webmail"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-16"
        comment = "Phishing Kit - Aruba - use Aruba_pec.php filename"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "Aruba_pec.php"
        $spec_file2 = "antispider.php"
        $spec_file3 = "clearsort1.php"
        $spec_file4 = "bt.php"
        $spec_file5 = "login.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
