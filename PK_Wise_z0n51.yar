rule PK_Wise_z0n51 : Wise
{
    meta:
        description = "Phishing Kit impersonating Wise.com"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-18"
        comment = "Phishing Kit - Wise.com - 'Main Author: Z0N51'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "auth"
        $spec_dir2 = "xN9dG1"
        // specific file found in PhishingKit
        $spec_file = "BrowserDetection.php"
        $spec_file2 = "app.php"
        $spec_file3 = "anti8.php"
        $spec_file4 = "app.webp"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
