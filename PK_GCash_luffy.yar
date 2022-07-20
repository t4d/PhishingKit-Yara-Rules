rule PK_GCash_luffy : GCash
{
    meta:
        description = "Phishing Kit impersonating GCash"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-20"
        comment = "Phishing Kit - GCash - 'Developed by ph.luffy 2021'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Gcash_database"
        $spec_dir2 = "Gcash_files"
        // specific file found in PhishingKit
        $spec_file = "gcash_logs.php"
        $spec_file2 = "mpin-login.php"
        $spec_file3 = "telegram-otp2.php"
        $spec_file4 = "wrong-mpin-login.php"
        $spec_file5 = "_admin.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}