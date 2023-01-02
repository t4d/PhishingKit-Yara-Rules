rule PK_BNP_ghayt : BNP
{
    meta:
        description = "Phishing Kit impersonating BNP Paribas"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-29"
        comment = "Phishing Kit - BNP - 'SCAMA WIDTH GHAYT'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir2 = "image"
        $spec_file1 = "Paiement-mobile-BNP-Paribas.png"
        $spec_file2 = "infos.php"
        $spec_file3 = "loading-end.php"
        $spec_file4 = "antibots__________GHAYT.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
