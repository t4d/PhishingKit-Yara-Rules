rule PK_Netflix_prohqcker : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-10-14"
        comment = "Phishing Kit - Netflix - using prohqcker.php file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "prohqcker.php"
        $spec_file2 = "MASTERCARD@2x.png"
        $spec_file3 = "VERVE@2x.png"
        $spec_file4 = "simplicity.51df52c550778103fe46.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
         all of ($spec_file*)
}
