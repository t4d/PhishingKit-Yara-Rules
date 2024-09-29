rule PK_Netflix_sql : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-09-29"
        comment = "Phishing Kit - Netflix - designed to use SQL DB"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "app"
        $spec_dir2 = "db"
        $spec_dir3 = "users"
        // specific file found in PhishingKit
        $spec_file = "chooseplan.php"
        $spec_file2 = "account.php"
        $spec_file3 = "indexx.php"
        $spec_file4 = "payment_method_init.php"
        $spec_file5= "ccs.sql"
        $spec_file6 = "nficon2016.ico"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
