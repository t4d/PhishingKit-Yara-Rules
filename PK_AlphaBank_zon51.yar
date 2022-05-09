rule PK_AlphaBank_zon51 : AlphaBank
{
    meta:
        description = "Phishing Kit impersonating Alpha Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-04"
        comment = "Phishing Kit - AlphaBank - 'Main Author: Z0N51'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_dir2 = "clients"
        $spec_file1 = "404.php"
        $spec_file2 = "visitors.html"
        $spec_file3 = "panel.php"
        $spec_file4 = "jquery.mask.js"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
