rule PK_Qoo10_boteyV15b : Qoo10
{
    meta:
        description = "Phishing Kit impersonating Qoo10"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-21"
        comment = "Phishing Kit - Qoo10 - 'BOTeye v1.5 Beta - Made by Cyborg99'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "picture_library"
        $spec_dir1 = "res"
        // specific file found in PhishingKit
        $spec_file = "security.html"
        $spec_file2 = "log5.php"
        $spec_file3 = "verification-loc=en_SG.requester=identity.html"
        $spec_file4 = "submission.html"
        $spec_file5 = "thank-you.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
