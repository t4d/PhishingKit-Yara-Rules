rule PK_BanquePostale_bpostal : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-03-06"
        comment = "Phishing kit - Banque Postale - '<bpostal@result.com>'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "secure"
        $spec_dir1 = "cap"
        // specific file found in PhishingKit
        $spec_file = "loading3.php"
        $spec_file2 = "cc.php"
        $spec_file3 = "cccc.png"
        $spec_file4 = "certicode.png"
        $spec_file5 = "pp.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}