rule PK_SwissPass_gxp : SwissPass
{
    meta:
        description = "Phishing Kit impersonating SwissPass.ch"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-08"
        comment = "Phishing Kit - SwissPass - '-GXP-'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "l3amer"
        $spec_dir2 = "scriptat"
        // specific file found in PhishingKit
        $spec_file = "kantonalbank.php"
        $spec_file2 = "maghat_lebssouch.js"
        $spec_file3 = "vuxe.php"
        $spec_file4 = "swisscard.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
