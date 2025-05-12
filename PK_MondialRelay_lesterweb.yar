rule PK_MondialRelay_lesterweb : MondialRelay
{
    meta:
        description = "Phishing Kit impersonating Mondial Relay"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-09"
        comment = "Phishing Kit - Mondial Relay - 'Author: LesterWeb'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "core"
        $spec_dir2 = "steps"
        // specific file found in PhishingKit
        $spec_file = "idontknow.php"
        $spec_file2 = "firewall.php"
        $spec_file3 = "ico_locker.svg"
        $spec_file4 = "logo_MR.png"
        $spec_file5 = "fevad.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
