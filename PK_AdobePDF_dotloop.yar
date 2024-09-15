rule PK_AdobePDF_dotloop : Adobe
{
    meta:
        description = "Phishing Kit impersonating Adobe PDF Online"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-28"
        comment = "Phishing Kit - Adobe PDF Online - 'From: Dotloop'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "asset" 
        // specific file found in PhishingKit
        $spec_file = "signin.php"
        $spec_file2 = "contract.jpg"
        $spec_file3 = "Microsoft_Edge_logo_(2019).svg.png"
        $spec_file4 = "KYC-ENG (confidential).pdf"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
