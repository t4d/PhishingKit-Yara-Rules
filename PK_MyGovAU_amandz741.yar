rule PK_MyGovAU_amandz741 : MyGovAU
{
    meta:
        description = "Phishing Kit impersonating MyGov Australian Government"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-02"
        comment = "Phishing kit - MyGovAU - 't.me/amandz741'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "rez"
        $spec_dir1 = "smsone_files"
        // specific file found in PhishingKit
        $spec_file = "addcc.php"
        $spec_file1 = "smszebi.php"
        $spec_file2 = "sendfull.php"
        $spec_file3 = "Mygov_Rzlt.txt"
        $spec_file4 = "mgv2-application.js.download"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
