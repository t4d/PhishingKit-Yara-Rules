rule PK_MyGovAU_elitesingles : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-13"
        comment = "Phishing kit - MyGovAU - 'EliteSingles'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir1 = "file"
        $spec_dir2 = "images"
        // specific file found in PhishingKit
        $spec_file = "detail.html"
        $spec_file2 = "thank.html"
        $spec_file3 = "d0c730269ecac3176c758ba99930a36fMy-Pension-Manager.xlsx"
        $spec_file4 = "mgv2-application.css"
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
