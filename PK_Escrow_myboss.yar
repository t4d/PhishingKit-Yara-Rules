rule PK_Escrow_myboss : Escrow
{
    meta:
        description = "Phishing Kit impersonating Escrow.com"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-25"
        comment = "Phishing Kit - Escrow - 'Cc: myboss@example.com'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "php"
        $spec_dir2 = "img"
        $spec_dir3 = "user"
        // specific file found in PhishingKit
        $spec_file = "process.php"
        $spec_file2 = "signup.php"
        $spec_file3 = "start_transaction.php"
        $spec_file4 = "mile.jpg"
        $spec_file5 = "reg.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
