rule PK_Ameli_dib : Ameli
{
    meta:
        description = "Phishing Kit impersonating Ameli.fr/Carte vitale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-03"
        comment = "Phishing Kit - Ameli/Carte vitale - 'Author : DIB'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "action"
        $spec_dir1 = "assets"
        $spec_dir2 = "images"
        $spec_file1 = "svg.php"
        $spec_file2 = "apple_pay.php"
        $spec_file3 = "vitale.jpg"
        $spec_file4 = "error_on_login.php"
        $spec_file5 = "loading_finished.php"

    condition:
        uint32(0) == 0x04034b50 and 
        $zip_file and 
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
