rule PK_FedEx_finx : FedEx
{
    meta:
        description = "Phishing Kit impersonating FedEx IL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-04-08"
        comment = "Phishing Kit - FedEx - 'RESULT BY Finx'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "action"
        $spec_dir2 = "killbot"
        // specific file found in PhishingKit
        $spec_file = "sms-sec.php"
        $spec_file2 = "settings.php"
        $spec_file3 = "forming-2.php"
        $spec_file4 = "test.css"
        $spec_file5 = "fx-favicon.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
