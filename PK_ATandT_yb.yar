rule PK_ATandT_yb : ATandT
{
    meta:
        description = "Phishing Kit impersonating ATandT"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-14"
        comment = "Phishing Kit - ATandT - 'Created By yb'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "AT&T.html"
        $spec_file2 = "now.php"
        $spec_file3 = "rd25RPk.png"
        $spec_file4 = "UNj1Ij7.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
