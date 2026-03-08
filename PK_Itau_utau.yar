rule PK_Itau_utau : Itau
{
    meta:
        description = "Phishing Kit impersonating Itaù bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-02-10"
        comment = "Phishing Kit - Itau - references to 'Utau'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "all.php"
        $spec_file2 = "succes.php"
        $spec_file3 = "sms-er.php"
        $spec_file4 = "login1.php"
        $spec_file5 = "itau_card_error.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        // check for file
        all of ($spec_file*)
}
