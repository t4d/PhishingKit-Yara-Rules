rule PK_BankOfAmerica_rd1218 : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-08"
        comment = "Phishing Kit - BankOfAmerica - 'CrEaTeD bY VeNzA'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "quest.html"
        $spec_file2 = "pas.html"
        $spec_file3 = "next.php"
        $spec_file4 = "bofa_icon_avoid_fraud.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
