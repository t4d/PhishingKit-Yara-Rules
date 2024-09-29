rule PK_Aruba_ar06 : Aruba
{
    meta:
        description = "Phishing Kit impersonating Aruba S.p.A."
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-04"
        comment = "Phishing Kit - Aruba - use ar06 directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "ar06"
        $spec_dir2 = "3D"
        $spec_dir3 = "cartasi"
        $spec_file1 = "sendother.php"
        $spec_file2 = "app.php"
        $spec_file3 = "smsok.php"
        $spec_file4 = "Codice O-Key SMS.php"
        $spec_file5 = "aruba_logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
