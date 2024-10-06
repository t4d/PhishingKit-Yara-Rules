rule PK_Aruba_corona : Aruba
{
    meta:
        description = "Phishing Kit impersonating Aruba S.p.A."
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - Aruba - 'By C0R0N1'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "areautenti"
        $spec_dir2 = "Haha"
        $spec_file1 = "tginfo.php"
        $spec_file2 = "akm.php"
        $spec_file3 = "2f.php"
        $spec_file4 = "09509_sia.v2.css"
        $spec_file5 = "4.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
