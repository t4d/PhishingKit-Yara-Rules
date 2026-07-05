rule PK_Nedbank_hemsworth : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-07"
        comment = "Phishing Kit - Nedbank - 'Author = Mac Hemsworth'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Hemsworth"
        $spec_dir2 = "skhid"
        $spec_dir3 = "trpnic"
        $spec_file = "nitrepnsa.php"
        $spec_file2 = "apvmstnr.php"
        $spec_file3 = "kljeram.php"
        $spec_file4 = "NedbankIcon.3cee39915afd52c3.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_file*) and
        all of ($spec_dir*)
}
