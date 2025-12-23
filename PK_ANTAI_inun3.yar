rule PK_antai_inun3 : ANTAI
{
    meta:
        description = "Phishing Kit impersonating French ANTAI (amendes) portal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-12-04"
        comment = "Phishing Kit - ANTAI - 'info@INUN.bg'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "infos_files"
        $spec_dir2 = "infoz"
        $spec_file1 = "infospage.php"
        $spec_file2 = "merci.php"
        $spec_file3 = "paiement.php"
        $spec_file4 = "sub_includes.php"
        $spec_file5 = "logo-amendes-gouv.svg"
        $spec_file6 = "main-es5.8d2eb497bdf1e092bf40.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
