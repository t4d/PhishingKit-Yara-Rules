rule PK_Telstra_flow : Telstra
{
    meta:
        description = "Phishing Kit impersonating Telstra"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-04-15"
        comment = "Phishing Kit - Telstra - using Flow.txt as exfil. file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "src"
        // specific file found in PhishingKit
        $spec_file = "cc.php"
        $spec_file2 = "Email.php"
        $spec_file3 = "smserror.php"
        $spec_file4 = "1.svg"
        $spec_file5 = "pn-blue.png"
        $spec_file6 = "done.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
