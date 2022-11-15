rule PK_AmericaFirst_RD983 : AmericaFirst
{
    meta:
        description = "Phishing Kit impersonating America First Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-14"
        comment = "Phishing Kit - America First - 'RD983'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir1 = "images"
        $spec_file1 = "card.html"
        $spec_file2 = "next.php"
        $spec_file3 = "app.76ff82e5.css"
        $spec_file4 = "logo-desktop-inverse.a3a99f3a.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
