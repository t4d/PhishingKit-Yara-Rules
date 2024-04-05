rule PK_Rafidain_robot : Rafidain
{
    meta:
        description = "Phishing Kit impersonating Rafidain Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-02-01"
        comment = "Phishing Kit - Rafidain - '$recipient_email = robot@rafidain-bank.online'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "uploadDir"
        $spec_dir2 = "uploads"

        // specific file found in PhishingKit
        $spec_file = "login.html"
        $spec_file2 = "process3.php"
        $spec_file3 = "scc3.css"
        $spec_file4 = "page2.html"
        $spec_file5 = "long.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
