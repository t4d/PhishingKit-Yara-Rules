rule PK_DKB_priv8: DKB
{
    meta:
        description = "Phishing Kit impersonating Das kann Bank (DKB)"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-25"
        comment = "Phishing Kit - DKB - 'PRIV8~bY~XauToL0g'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "snd"
        $spec_dir2 = "login_fichiers"
        $spec_file1 = "app_karte.php"
        $spec_file2 = "meine-Bevestiging.php"
        $spec_file3 = "binary_app.php"
        $spec_file4 = "dkb-global.htm"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
