rule PK_Amex_systembott : Amex
{
    meta:
        description = "Phishing Kit impersonating American Express"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-09-17"
        comment = "Phishing Kit - Amex - '-|@systembott|-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "index.html"
        $spec_file2 = "panel.php"
        $spec_file3 = "res.php"
        $spec_file4 = "save.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_file*)
}
