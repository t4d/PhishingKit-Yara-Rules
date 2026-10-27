rule PK_Nedbank_hemsworth2 : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-10-25"
        comment = "Phishing Kit - Nedbank - 'Author = Mac Hemsworth'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Hemsworth"
        $spec_dir2 = "Decmar"
        $spec_dir3 = "ciboern"
        $spec_file = "Abcd.php"
        $spec_file2 = "Sendmodule.php"
        $spec_file3 = "ricercos6.php"
        $spec_file4 = "NedbankIcon.3cee39915afd52c3.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_file*) and
        all of ($spec_dir*)
}
