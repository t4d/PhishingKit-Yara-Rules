rule PK_Ameli_sunrise22 : Ameli
{
    meta:
        description = "Phishing Kit impersonating Ameli.fr/Carte vitale"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-25"
        comment = "Phishing Kit - Ameli/Carte vitale"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "actions"
        $spec_dir1 = "prevents"
        $spec_dir2 = "steps"
        $spec_file1 = "avoir.php"
        $spec_file2 = "error_on_login.php.php"
        $spec_file3 = "vitale.jpg"
        $spec_file4 = "card.php"
        $spec_file5 = "anti8.php"

    condition:
        uint32(0) == 0x04034b50 and 
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
