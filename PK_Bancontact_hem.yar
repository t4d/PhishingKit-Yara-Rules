rule PK_Bancontact_hem : Bancontact
{
    meta:
        description = "Phishing Kit impersonating Bancontact"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-28"
        comment = "Phishing kit impersonating Bancontact - '-- BY Mr.hem  --'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "data"
        $spec_dir2 = "dist"
        $spec_dir3 = "file"
        $spec_file = "bancontact.html"
        $spec_file2 = "demo.html"
        $spec_file3 = "super.php"
        $spec_file4 = "go.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        all of ($spec_file*)
}
