rule PK_UPS_z0n51 : UPS
{
    meta:
        description = "Phishing Kit impersonating UPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-15"
        comment = "Phishing Kit - UPS - 'Z0N51'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "clients"
        $spec_dir2 = "inacho"
        // specific file found in PhishingKit
        $spec_file = "q.png"
        $spec_file2 = "helpers.css"
        $spec_file3 = "sms.php"
        $spec_file4 = "defender.php"
        $spec_file5 = "mobilemenu-fr.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
