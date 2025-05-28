rule PK_Maybank_2e : Maybank
{
    meta:
        description = "Phishing Kit impersonating Maybank2E"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-28"
        comment = "Phishing Kit - Maybank - Mayban2E"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "m2e.html"
        $spec_file2 = "formm2e2.php"
        $spec_file3 = "nohp.html"
        $spec_file4 = "token.html"
        $spec_file5 = "formm2e.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
