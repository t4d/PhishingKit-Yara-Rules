rule PK_Wsecu_prohqcker : WSECU
{
    meta:
        description = "Phishing Kit impersonating WSECU, Washington State Employees Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-12"
        comment = "Phishing Kit - WSECU - '*Prohqcker***WSECU***'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "WSECU"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "c.html"
        $spec_file1 = "personal.html"
        $spec_file2 = "prohqcker4.php"
        $spec_file3 = "theme-wsecu-retail.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
