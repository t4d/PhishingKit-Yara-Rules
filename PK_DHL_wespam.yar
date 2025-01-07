rule PK_DHL_wespam : DHL
{
    meta:
        description = "Phishing Kit impersonating DHL"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-01-03"
        comment = "Phishing Kit - DHL - 'DHL V3 by @WESPAM25'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "all_mixing"
        $spec_dir2 = "send"
        $spec_file1 = "postsmserr.php"
        $spec_file2 = "postrz.php"
        $spec_file3 = "jq.js"
        $spec_file4 = "titiza.png"
        $spec_file5 = "dhl-logo.svg"
        
    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
