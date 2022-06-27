rule PK_Generic_xclusiv : xclusiv_Generic
{
    meta:
        description = "Phishing Kit - xclusiv - Generic email credentials stealer"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-24"
        comment = "Phishing Kit - 'xclusiv-Czer'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "FILES"
        // specific file found in PhishingKit
        $spec_file = "ie7hacks.css"
        $spec_file2 = "connectID.php"
        $spec_file3 = "success.php"
        $spec_file4 = "x4d.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

