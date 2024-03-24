rule PK_Huntington_yochi : Huntington
{
    meta:
        description = "Phishing Kit impersonating Huntington bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-29"
        comment = "Phishing Kit - Huntington Bank - 'Yochi FUD Page'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "render"
        $spec_dir2 = "config"
        $spec_dir3 = "admin"
        $spec_file = "oo.php"
        $spec_file2 = "2be3.php"
        $spec_file3 = "live.php"
        $spec_file4 = "HuntingtonApexWeb-Bold.woff"
        $spec_file5 = "huntfav.ico"
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        all of ($spec_file*)
}
