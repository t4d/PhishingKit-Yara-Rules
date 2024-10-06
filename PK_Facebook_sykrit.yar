rule PK_Facebook_sykrit : Facebook
{
    meta:
        description = "Phishing Kit impersonating Facebook"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-10-04"
        comment = "Phishing Kit - Facebook - 'This scam created by SykRit'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "mbasic"
        $spec_dir2 = "mobile"
        $spec_dir3 = "fb"
        // specific file found in PhishingKit
        $spec_file = "x.php"
        $spec_file1 = "sykrit.txt"
        $spec_file2 = "O2aKM2iSbOw.png"
        $spec_file3 = "Scam_1_Type.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
