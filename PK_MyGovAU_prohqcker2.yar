rule PK_MyGovAU_prohqcker2 : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-28"
        comment = "Phishing kit - MyGovAU - 'Prohqcker Magic***A-T-O'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "BOTS"
        $spec_dir1 = "file"
        $spec_dir2 = "stylesheet"
        // specific file found in PhishingKit
        $spec_file = "d.html"
        $spec_file2 = "me.php"
        $spec_file3 = "otp2.html"
        $spec_file4 = "blugov.css"
        $spec_file5 = "myGov-cobranded-logo-black.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
