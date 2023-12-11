rule PK_impots_gouv_fr_zb : impots_gouv_fr
{
    meta:
        description = "Phishing Kit impersonating impots.gouv.fr"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-30"
        comment = "Phishing Kit - impots.gouv.fr - 'using zb.php'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_dir1 = "polices"
        $spec_dir2 = "dyn"
        $spec_file1 = "zb.php"
        $spec_file2 = "rs.html"
        $spec_file3 = "Logaccess.php"
        $spec_file4 = "__CONFIG__.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
