rule PK_ANTAI_db : ANTAI
{
    meta:
        description = "Phishing Kit impersonating French ANTAI (amendes) portal"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-08-01"
        comment = "Phishing Kit - ANTAI - using database to store data"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "iframe"
        $spec_dir2 = "cache"
        $spec_file1 = "visitors.db"
        $spec_file2 = "app.php"
        $spec_file3 = "init.php"
        $spec_file4 = "logo-amendes-gouv.svg"
        $spec_file5 = "marianne-regular.woff"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
