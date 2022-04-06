rule PK_WellsFargo_anoxyty : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-20"
        comment = "Phishing Kit - Wells Fargo - '[ WellsFargo By Anoxyty | ]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "secure"
        // specific file found in PhishingKit
        $spec_file = "carrz.php"
        $spec_file2 = "billres.php"
        $spec_file3 = "scrmderrs.php"
        $spec_file4 = "websafed.php"
        $spec_file5 = "yours.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
