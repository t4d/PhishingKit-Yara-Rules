rule PK_NAB_echovsl : NAB
{
    meta:
        description = "Phishing Kit impersonating National Australia Bank (NAB)"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-10-08"
        comment = "Phishing kit - NAB - 'TELEGRAM: ECHOVSL'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "script"
        // specific file found in PhishingKit
        $spec_file = "fxker.php"
        $spec_file2 = "auth3.html"
        $spec_file3 = "edit.php"
        $spec_file4 = "security.html"
        $spec_file5 = "star-big.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
