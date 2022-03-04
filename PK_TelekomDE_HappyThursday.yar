rule PK_TelekomDE_HappyThursday : TelekomDE
{
    meta:
        description = "Phishing Kit impersonating Telekom Deutschland GmbH"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2022-03-01"
        comment = "Phishing Kit - Telekom DE - 'From: HappyThursday'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "index_files"
        // specific file found in PhishingKit
        $spec_file = "login2.php" nocase
        $spec_file2 = "index.html"
        $spec_file3 = "services.png"
        $spec_file4 = "wt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and 
        // check for file
        all of ($spec_file*)
}

