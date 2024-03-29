rule PK_antai_hera : ANTAI
{
    meta:
        description = "Phishing Kit impersonating French ANTAI (amendes) portal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://youtu.be/wPccXwmgBK8"
        date = "2024-03-28"
        comment = "Phishing Kit - ANTAI - 'using hera.php'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_file1 = "hera.php"
        $spec_file2 = "her.php"
        $spec_file3 = "formulaire2.php"
        $spec_file4 = "traiter2.php"
        $spec_file5 = "logi.png"
        $spec_file6 = "88.jpeg"
        $spec_file7 = "controle.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_file*)
}
