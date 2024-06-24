rule PK_BRI_sadapan : BRI
{
    meta:
        description = "Phishing Kit impersonating Bank Rakyat Indonesia (BRI)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-03"
        comment = "Phishing Kit - BRI - TG botname: 'sadapan'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "auth"
        $spec_dir2 = "img"
        $spec_dir3 = "fonts"
        // specific file found in PhishingKit
        $spec_file = "ottp.php"
        $spec_file2 = "valid.php"
        $spec_file3 = "blm.php"
        $spec_file4 = "nobit.php"
        $spec_file5 = "screenshot_20240324_154352_brimo-AQEVrzErBrh31lqL.jpg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
