rule PK_USPS_ah47 : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-06"
        comment = "Phishing Kit - USPS - 'fwrite($file, $Ak47)'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "assets"
        $spec_dir2 = "img"
        $spec_dir3 = "fonts"
        $spec_dir4 = "usps"
        // specific file found in PhishingKit
        $spec_file = "5.php"
        $spec_file2 = "useragent.txt"
        $spec_file3 = "sms3.html"
        $spec_file4 = "Bootstrap-Payment-Form-.css"
        $spec_file5 = "accepted_cards.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
