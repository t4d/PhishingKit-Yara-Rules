rule PK_Netflix_zephyr : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-12-23"
        comment = "Phishing Kit - Netflix - ZephyrScama"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "app"
        $spec_dir2 = "scama"
        $spec_dir3 = "_config"
        // specific file found in PhishingKit
        $spec_file = "nficon2016.png"
        $spec_file2 = "icon_cartes_bancaires_2x.png"
        $spec_file3 = "vbv.php"
        $spec_file4 = "loginBase.09e271325f8873705389.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
