rule PK_Nedbank_kanrun : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-09-15"
        comment = "Phishing Kit - Nedbank - 'From: kanrun'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "rmcsn"
        $spec_dir2 = "rnet"
        // specific file found in PhishingKit
        $spec_file = "myportalndb.php"
        $spec_file2 = "merot.php"
        $spec_file3 = "acceptverc.php"
        $spec_file4 = "bgns.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
