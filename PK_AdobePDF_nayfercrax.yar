rule PK_AdobePDF_nayfercrax : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-05"
        comment = "Phishing Kit - Adobe PDF Online - 'Coded by @nayfercrax'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "email"
        $spec_dir1 = "myconfig"
        $spec_dir2 = "api"
        // specific file found in PhishingKit
        $spec_file = "kill.txt"
        $spec_file2 = "aol.php"
        $spec_file3 = "microsoft.php"
        $spec_file4 = "telegram.php"
        $spec_file5 = "microsoft_logo.svg"
        $spec_file6 = "CTZ_Green-01.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
