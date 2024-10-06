rule PK_BRI_tarip : BRI
{
    meta:
        description = "Phishing Kit impersonating Bank Rakyat Indonesia (BRI)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-30"
        comment = "Phishing Kit - BRI - 'BRI TARIP'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "req"
        $spec_dir2 = "img"
        // specific file found in PhishingKit
        $spec_file = "saldo.php"
        $spec_file2 = "no.php"
        $spec_file3 = "4.js"
        $spec_file4 = "vibr.js"
        $spec_file5 = "1703668668502.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
