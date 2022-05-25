rule PK_Generic_Z10n : Z10n_Generic
{
    meta:
        description = "Phishing Kit - Z10n - Generic email credentials stealer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-23"
        comment = "Phishing Kit - '- by Z10n -'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Admin"
        // specific file found in PhishingKit
        $spec_file = "acct.php"
        $spec_file2 = "adm.html"
        $spec_file3 = "Finish.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

