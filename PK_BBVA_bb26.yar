rule PK_BBVA_bb26 : BBVA
{
    meta:
        description = "Phishing Kit impersonating BBVA"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-05-13"
        comment = "Phishing Kit - BBVA - found named bb26final.zip"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "principal"
        $spec_dir2 = "productos nuevos"
        $spec_dir3 = "teclado"
        $spec_file1 = "dni.php"
        $spec_file2 = "key.php"
        $spec_file3 = "on.php"
        $spec_file4 = "config.ini"
        $spec_file5 = "logoBN.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
