rule PK_Ent_xxx : Ent
{
    meta:
        description = "Phishing Kit impersonating Ent Online Banking"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-15"
        comment = "Phishing Kit - Ent"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "Financial"
        $spec_dir2 = "Ownership"
        $spec_dir3 = "Start"
        $spec_file1 = "indexx.html"
        $spec_file2 = "success.html"
        $spec_file3 = "grabber.php"
        $spec_file4 = "indexsq.html"
        $spec_file5 = "ent.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
