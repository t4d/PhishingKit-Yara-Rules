rule PK_MondialRelay_traffyque : MondialRelay
{
    meta:
        description = "Phishing Kit impersonating Mondial Relay"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-29"
        comment = "Phishing Kit - MondialRelay - 'Traffyque'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "panel"
        $spec_dir2 = "actions"
        $spec_dir3 = "enc"

        // specific file found in PhishingKit
        $spec_file = "error.php"
        $spec_file2 = "billing-info.php"
        $spec_file3 = "loading-visa-verification.php"
        $spec_file4 = "3d secure visa.php"
        $spec_file5 = "colis.png"
        $spec_file6 = "thegreenweb-mondialrelayfr.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
