rule PK_Facebook_red : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-11"
        comment = "Phishing Kit - Facebook - 'const red__'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "recp"
        $spec_dir2 = "img"
        // specific file found in PhishingKit
        $spec_file = "auth.htm"
        $spec_file1 = "mlogin.html"
        $spec_file2 = "config.js"
        $spec_file3 = "fbDlm.css"
        $spec_file4 = "wasap.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
