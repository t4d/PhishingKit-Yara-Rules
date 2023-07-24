rule PK_EmailVerif_passd : Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-20"
        comment = "Phishing Kit - Email Verification"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "login_files"
        $spec_dir2 = "img"
        // specific file found in PhishingKit
        $spec_file = "login.php"
        $spec_file2 = "logo.png"
        $spec_file3 = "loginBasic.css"
        $spec_file4 = "loginAdvanced.css"
        $spec_file5 = "middle.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
