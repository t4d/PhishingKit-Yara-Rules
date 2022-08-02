rule PK_USPS_ard8no : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-08"
        comment = "Phishing Kit - USPS - 'ard8no das'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "verification"
        $spec_dir2 = "rez"
        // specific file found in PhishingKit
        $spec_file = "payment.php"
        $spec_file2 = "sms2.php"
        $spec_file3 = "wait.php"
        $spec_file4 = "send4.php"
        $spec_file5 = "schedule-redelivery.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
