rule PK_FifthThirdBank_b64 : FifthThirdBank
{
    meta:
        description = "Phishing Kit impersonating Fifth Third Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-23"
        comment = "Phishing Kit - Fifth Third Bank - Base64 obfuscation used on PHP files"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Cm"
        $spec_dir2 = "signal"
        // specific file found in PhishingKit
        $spec_file = "indexem.php"
        $spec_file2 = "grabber.php"
        $spec_file3 = "process3.php"
        $spec_file4 = "ng8.bundle.min.ffb4e1.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}