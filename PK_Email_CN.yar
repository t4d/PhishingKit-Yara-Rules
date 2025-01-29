rule PK_Email_CN : Email
{
    meta:
        description = "Phishing Kit stealing email credentials from 126 and 163.com"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-25"
        comment = "Phishing Kit - Email - 'Scripted by Machine'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "126"
        $spec_dir2 = "163"
        // specific file found in PhishingKit
        $spec_file = "loading.php"
        $spec_file2 = "login.php"
        $spec_file3 = "126.jpg"
        $spec_file4 = "163_bkg.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
