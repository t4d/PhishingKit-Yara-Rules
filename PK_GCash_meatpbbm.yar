rule PK_GCash_meatpbbm : GCash
{
    meta:
        description = "Phishing Kit - RD337 - impersonating GCash.com"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-05-09"
        comment = "Phishing Kit - GCash - 'meatpbbm' string for home dir. in error_logs"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "online"
        // specific file found in PhishingKit
        $spec_file = "gcash-1024x768.png"
        $spec_file2 = "index-info.php"
        $spec_file3 = "mpin-info.php"
        $spec_file4 = "otp-info.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}

