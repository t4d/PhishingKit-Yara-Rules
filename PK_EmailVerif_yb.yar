rule PK_EmailVerif_yb : Email_verification
{
    meta:
        description = "Phishing Kit stealing email credentials"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-13"
        comment = "Phishing Kit - Email Verification - 'Created By yb'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        // specific file found in PhishingKit
        $spec_file = "Message.txt"
        $spec_file2 = "post.php"
        $spec_file3 = "pass.php"
        $spec_file4 = "connect.html"
        $spec_file5 = "id.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
