rule PK_Vestel_girisli : Vestel
{
    meta:
        description = "Phishing Kit impersonating Vestel"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-09-27"
        comment = "Phishing Kit - Vestel - '$girisli'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "dekontlar"
        $spec_file1 = "siparis_kaydet.php"
        $spec_file2 = "odeme.php"
        $spec_file3 = "db.php"
        $spec_file4 = "kredikartyok.mp4"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
