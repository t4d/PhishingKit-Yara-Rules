rule PK_EmiratesPost_azar : EmiratesPost
{
    meta:
        description = "Phishing Kit impersonating EmiratesPost"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-26"
        comment = "Phishing Kit - EmiratesPost - 'Make By ==> Telegram : @Azar_ox'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "anti__boot"
        $spec_dir2 = "all_mixing"
        // specific file found in PhishingKit
        $spec_file = "cc.php"
        $spec_file2 = "loading_4.php"
        $spec_file3 = "sms_err.php"
        $spec_file4 = "Emarats.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*) 
}
