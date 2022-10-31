rule PK_Excel_511 : Excel
{
    meta:
        description = "Phishing Kit impersonating Excel page"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-12"
        comment = "Phishing Kit - Excel - contain 511.php file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "ajax.googleapis.com"
        $spec_dir2 = "js"
        // specific file found in PhishingKit
        $spec_file = "511.php"
        $spec_file2 = "tether.js"
        $spec_file3 = "scripts.js"
        $spec_file4 = "spinner.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
