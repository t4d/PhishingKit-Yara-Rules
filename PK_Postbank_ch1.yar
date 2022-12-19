rule PK_Postbank_ch1 : Postbank
{
    meta:
        description = "Phishing Kit impersonating Postbank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-12-05"
        comment = "Phishing Kit - Postbank - 'CH1_Postbank'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "ses"
        $spec_dir1 = "Login"
        $spec_dir2 = "bots"
        // specific file found in PhishingKit
        $spec_file = "SendLogin.php"
        $spec_file2 = "SendSMS.php"
        $spec_file3 = "sms-error.php"
        $spec_file4 = "visit.html"
        $spec_file5 = "config.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
