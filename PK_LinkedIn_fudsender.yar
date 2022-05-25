rule PK_LinkedIn_fudsender : LinkedIn
{
    meta:
        description = "Phishing Kit impersonating LinkedIn"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-24"
        comment = "Phishing Kit - LinkedIn - '- fudsender(dot)com -'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "email.php"
        $spec_file2 = "lin.ico"
        $spec_file3 = "next.php"
        $spec_file4 = "jquery-3.2.1.slim.min.js"
        $spec_file5 = "bg.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and 
        // check for files
        all of ($spec_file*)
}
