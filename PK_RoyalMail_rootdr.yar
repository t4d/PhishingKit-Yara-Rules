rule PK_RoyalMail_rootdr : RoyalMail
{
    meta:
        description = "Phishing Kit impersonating RoyalMail"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-26"
        comment = "Phishing Kit - RoyalMail - 'BLACKFORCE REZDATA' 'Coded By Root_Dr'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "prevents"
        $spec_dir2 = "botActVbv"
        // specific file found in PhishingKit
        $spec_file = "payment.php"
        $spec_file2 = "infoz.php"
        $spec_file3 = "panel.php"
        $spec_file4 = "css_2kSODmeFaX7ybMB6AeohAt_hNxiz95dKI0JJ2-F4f_k.css"
        $spec_file5 = "blackforce.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
