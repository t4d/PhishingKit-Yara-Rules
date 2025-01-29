rule PK_Doctolib_js : Doctolib
{
    meta:
        description = "Phishing Kit impersonating Doctolib"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-25"
        comment = "Phishing Kit - Doctolib"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "webpack"
        $spec_dir2 = "app"
        $spec_file1 = "letter.php"
        $spec_file2 = "facturation.php"
        $spec_file3 = "paiement.php"
        $spec_file4 = "success.php"
        $spec_file5 = "Cards_Credit-Vitale-coins.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
