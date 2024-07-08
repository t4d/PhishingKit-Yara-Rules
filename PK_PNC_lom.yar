rule PK_PNC_lom : PNC
{
    meta:
        description = "Phishing Kit impersonating PNC online bank"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-05-13"
        comment = "Phishing Kit - PNC - 'lom@pnc.c0m'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "pnc"
        // specific file found in PhishingKit
        $spec_file = "finish.php"
        $spec_file2 = "index.html"
        $spec_file3 = "index.php"
        $spec_file4 = "securityupdate.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
