    rule PK_MTBank_yochi2 : MT_Bank
    {
        meta:
            description = "Phishing Kit impersonating M&T Bank"
            licence = "AGPL-3.0"
            author = "Thomas 'tAd' Damonneville"
            reference = ""
            date = "2025-03-02"
            comment = "Phishing Kit - M&T Bank - 'From: YoCHI'"

        strings:
            // the zipfile working on
            $zip_file = { 50 4b 03 04 }
            $spec_dir = "autob"
            $spec_dir1 = "admin"
            // specific files found in PhishingKit
            $spec_file = "bts2.php"
            $spec_file2 = "logov.php"
            $spec_file3 = "susps.php"
            $spec_file4 = "refspam.php"
            $spec_file5 = "mtb-logo.svg"

        condition:
            // look for the ZIP header
            uint32(0) == 0x04034b50 and
            // make sure we have a local file header
            $zip_file and
            all of ($spec_dir*) and 
            // check for file
            all of ($spec_file*) 
    }
