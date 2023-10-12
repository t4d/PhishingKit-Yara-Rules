rule PK_Facebook_ditznesia : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-05"
        comment = "Phishing Kit - Facebook - 'Copyright © Ditznesia'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "data"
        $spec_dir2 = "ditznesia"
        // specific file found in PhishingKit
        $spec_file = "visitor.json"
        $spec_file1 = "final.php"
        $spec_file2 = "UpdateData.php"
        $spec_file3 = "data.json"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
