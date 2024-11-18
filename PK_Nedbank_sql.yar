rule PK_Nedbank_sql : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-11-11"
        comment = "Phishing Kit - Nedbank - using SQLite database"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "scripts"
        $spec_dir2 = "phpliteadmin"
        // specific file found in PhishingKit
        $spec_file = "NedbankMoney.htm"
        $spec_file2 = "read.php"
        $spec_file3 = "NedMoney~ATMCARDS~LIMITS.htm"
        $spec_file4 = "NedbankLogin_v7.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
