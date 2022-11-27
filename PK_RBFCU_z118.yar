rule PK_RBFCU_z118 : RBFCU
{
    meta:
        description = "Phishing Kit impersonating Randolph-Brooks Federal Credit Union"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-10-07"
        comment = "Phishing Kit - RBFCU - '$Z118_EMAIL'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directories found in PhishingKit
        $spec_dir = "functions"
        $spec_dir1 = "grabber"
        // specific file found in PhishingKit
        $spec_file = "config.php"
        $spec_file2 = "rbfcu-logo.svg"
        $spec_file3 = "session_login.php"
        $spec_file4 = "Thankyou.php"
        $spec_file5 = "CARD.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
