rule PK_LinkedIn_fixsweb : LinkedIn
{
    meta:
        description = "Phishing Kit impersonating LinkedIn"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-11-07"
        comment = "Phishing Kit - LinkedIn - '-[ FIXSWEB_Linkedln]-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "prevents"
        $spec_dir1 = "sc"
        $spec_file1 = "login.php"
        $spec_file2 = "email.php"
        $spec_file3 = "gg.html"
        $spec_file4 = "dhra8axxv5afjd3u90gduwpcj.png"
        $spec_file5 = "blocker.txt"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        // check for files
        all of ($spec_file*)
}
