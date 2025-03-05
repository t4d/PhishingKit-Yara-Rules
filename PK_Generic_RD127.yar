rule PK_Generic_RD127 : RD127_Generic
{
    meta:
        description = "Phishing Kit - RD127 - Generic email credentials stealer"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-03"
        comment = "Phishing Kit - RD127"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "images"
        $spec_dir2 = "css"
        // specific file found in PhishingKit
        $spec_file = "weblogo.png"
        $spec_file2 = "next.php"
        $spec_file3 = "email.php"
        $spec_file4 = "index.html"
        $spec_file5 = "landing.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
