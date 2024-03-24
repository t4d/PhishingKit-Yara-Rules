rule PK_Nedbank_xxxcashout2 : Nedbank
{
    meta:
        description = "Phishing Kit impersonating Nedbank"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-01-23"
        comment = "Phishing Kit - Nedbank - 'XXXCASHOUT' - version 2"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "zzz"
        $spec_dir2 = "app"
        // specific file found in PhishingKit
        $spec_file = "post3.php"
        $spec_file2 = "app-confirmation.php"
        $spec_file3 = "otp-verification.php"
        $spec_file4 = "Email.php"
        $spec_file5 = "Eye-Hide.105fff437c32e67f.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
