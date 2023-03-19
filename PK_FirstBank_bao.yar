rule PK_FirstBank_bao : FirstBank
{
    meta:
        description = "Phishing Kit impersonating First Bank & Trust"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-17"
        comment = "Phishing Kit - First Bank Texas - 'Created BY @Dev.Bao on ICQ'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Phone"
        $spec_dir2 = "Sign-On"
        // specific file found in PhishingKit
        $spec_file = "telegram-send.php"
        $spec_file2 = "send-otp.php"
        $spec_file3 = "logger.php"
        $spec_file4 = "logscript.js"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
