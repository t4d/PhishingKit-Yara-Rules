rule PK_Nickel_tahma9 : Nickel
{
    meta:
        description = "Phishing Kit impersonating Nickel"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-10"
        comment = "Phishing Kit - Nickel - 'TG bot name tahma9_bot'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "clients"
        $spec_dir2 = "fucked"
        // specific file found in PhishingKit
        $spec_file = "auth.php"
        $spec_file2 = "c94c03d8.png"
        $spec_file3 = "informations.php"
        $spec_file4 = "sms.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
