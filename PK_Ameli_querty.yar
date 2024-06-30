rule PK_Ameli_querty : Ameli
{
    meta:
        description = "Phishing Kit impersonating Ameli.fr/Carte vitale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-30"
        comment = "Phishing Kit - Ameli/Carte vitale - 'Ameli Querty billing'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "action"
        $spec_dir2 = "prevents"
        $spec_dir3 = "panel"
        $spec_file1 = "infos.php"
        $spec_file2 = "avcard.php"
        $spec_file3 = "confirme.php"
        $spec_file4 = "click.txt"
        $spec_file5 = "stats.ini"

    condition:
        uint32(0) == 0x04034b50 and 
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
