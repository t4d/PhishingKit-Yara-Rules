rule PK_MTBank_venza : MT_Bank
{
    meta:
        description = "Phishing Kit impersonating M&T Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-27"
        comment = "Phishing Kit - M&T Bank - '- CrEaTeD bY VeNzA -'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "smoth"
        $spec_dir1 = "includes"
        // specific files found in PhishingKit
        $spec_file = "em.html"
        $spec_file2 = "user_details.php"
        $spec_file3 = "config.php"
        $spec_file4 = "detail.html"
        $spec_file5 = "mtb-logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*) 
}
