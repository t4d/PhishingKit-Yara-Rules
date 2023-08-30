rule PK_Ameli_clack : Ameli
{
    meta:
        description = "Phishing Kit impersonating Ameli.fr/Carte vitale"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-08-29"
        comment = "Phishing Kit - Ameli/Carte vitale - 'By clack'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_fichiers"
        $spec_file1 = "send.php"
        $spec_file2 = "merci.php"
        $spec_file3 = "gen_validatorv4.js"
        $spec_file4 = "tetiere_regime_general.png"
        $spec_file5 = "biblicnam-structure-sans.css"

    condition:
        uint32(0) == 0x04034b50 and 
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
