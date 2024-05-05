rule PK_Generic_verifycn : verifyCN_Generic
{
    meta:
        description = "Phishing Kit - Z10n - Generic email credentials stealer"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-09"
        comment = "Phishing Kit - 'From: VerifyCN'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "support"
        // specific file found in PhishingKit
        $spec_file = "access1.php"
        $spec_file1 = "access2.php"
        $spec_file2 = "auth.php"
        $spec_file3 = "go.php"
        $spec_file4 = "modal.jpg"
        $spec_file5 = "signin.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
