rule PK_AmericaFirst_packaging : AmericaFirst
{
    meta:
        description = "Phishing Kit impersonating America First Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-26"
        comment = "Phishing Kit - America First - 'From: Packaging'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "img"
        $spec_dir1 = "css"
        $spec_file1 = "c.html"
        $spec_file2 = "db_connect5.php"
        $spec_file3 = "RadDockableObject.css"
        $spec_file4 = "BANGOR.png"
        $spec_file5 = "security.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
