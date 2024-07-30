rule PK_Netflix_ug3yo : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-25"
        comment = "Phishing Kit - Netflix - 'UG3YO SP NETFLIX LOGIN'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "workshop"
        $spec_dir2 = "app"
        // specific file found in PhishingKit
        $spec_file = "step4.php"
        $spec_file2 = "mine.php"
        $spec_file3 = "none2.css"
        $spec_file4 = "nf-icon-v1-93.ttf"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
