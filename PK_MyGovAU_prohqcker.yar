rule PK_MyGovAU_prohqcker : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-12"
        comment = "Phishing kit - MyGovAU - 'Telegram ID: @prohqcker'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir1 = "images"
        // specific file found in PhishingKit
        $spec_file = "mgv2-application.css"
        $spec_file1 = "c.html"
        $spec_file2 = "personal.html"
        $spec_file3 = "prohqcker4.php"
        $spec_file4 = "D-myGov-Coloured%20Line.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
