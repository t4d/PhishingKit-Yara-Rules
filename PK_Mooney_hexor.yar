rule PK_Mooney_hexor : Mooney
{
    meta:
        description = "Phishing Kit impersonating Mooney.it"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-06-09"
        comment = "Phishing Kit - Mooney - using '$hexor' variable"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "online"
        $spec_dir2 = "del"

        // specific file found in PhishingKit
        $spec_file = "incsms.php"
        $spec_file2 = "TelegramApi.php"
        $spec_file3 = "hexor.css"
        $spec_file4 = "logo-mooney.1330f350147445f5103b36dac80a6726.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and
        all of ($spec_dir*)
}
