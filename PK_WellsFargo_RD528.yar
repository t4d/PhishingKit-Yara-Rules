rule PK_WellsFargo_RD528 : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-19"
        comment = "Phishing Kit - Wells Fargo - using RD528 in archive name - reference to 'venza'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        // specific file found in PhishingKit
        $spec_file = "rout.html"
        $spec_file2 = "parse.php"
        $spec_file3 = "email.php"
        $spec_file4 = "detail.html"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}