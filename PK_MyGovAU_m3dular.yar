rule PK_MyGovAU_m3dular : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-16"
        comment = "Phishing kit - MyGovAU - 'Built by @m3dular'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Sign-in - myGov_files"
        $spec_dir1 = "m3dularbh"
        // specific file found in PhishingKit
        $spec_file = "m3dular_config.php"
        $spec_file2 = "blacktds.php"
        $spec_file3 = "payment.html"
        $spec_file4 = "mygov-logo.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
