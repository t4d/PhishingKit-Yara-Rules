rule PK_Schwab_rd588 : Schwab
{
    meta:
        description = "Phishing Kit impersonating Schwab.com"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-06"
        comment = "Phishing Kit - Schwab.com - RD588 - 'CrEaTeD bY VeNzA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "detail.html"
        $spec_file2 = "next.php"
        $spec_file3 = "login-component-responsive-secondary.css"
        $spec_file4 = "sdps.css"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
