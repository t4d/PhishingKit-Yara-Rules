rule PK_Netflix_letter : Netflix
{
    meta:
        description = "Phishing Kit impersonating Netflix"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-16"
        comment = "Phishing Kit - Netflix - with a HTML letter draft"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "actions"
        $spec_dir1 = "steps"
        $spec_dir2 = "prevents"
        // specific file found in PhishingKit
        $spec_file = "Letter.html"
        $spec_file2 = "error_on_login.php"
        $spec_file3 = "loading_apple_pay.php"
        $spec_file4 = "timer_finished.js"
        $spec_file5 = "cloudflare.jpg"
        $spec_file6 = "key.inc.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
