rule PK_Facebook_wa : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-25"
        comment = "Phishing Kit - Facebook - using WhatsApp page"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "etc"
        $spec_dir1 = "img"
        $spec_dir2 = "setting"
        // specific file found in PhishingKit
        $spec_file = "visitor.json"
        $spec_file1 = "antispam.json"
        $spec_file2 = "data.json"
        $spec_file3 = "data.php"
        $spec_file4 = "logowa.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
