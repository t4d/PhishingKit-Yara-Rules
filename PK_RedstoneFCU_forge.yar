rule PK_RedstoneFCU_forge : RedstoneFCU
{
    meta:
        description = "Phishing Kit impersonating Redstone Federal Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-17"
        comment = "Phishing Kit - Redstone Federal Credit Union - 'From: xforgex'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "session"
        $spec_dir2 = "a_data"
        // specific file found in PhishingKit
        $spec_file = "sbretry.php"
        $spec_file2 = "sbcodet.php"
        $spec_file3 = "retry.php"
        $spec_file4 = "Dila_DZ.php"
        $spec_file5 = "05345-logo-sm-xs-publish.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
