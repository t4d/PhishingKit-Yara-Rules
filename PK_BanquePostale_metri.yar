rule PK_BanquePostale_metri : Banque Postale
{
    meta:
        description = "Phishing Kit impersonating la Banque Postale"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-05"
        comment = "Phishing kit - Banque Postale - 'Postale log By METRI'"        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "society-assets"
        $spec_dir1 = "METRI"
        // specific file found in PhishingKit
        $spec_file = "done.jpg"
        $spec_file2 = "ss2.php"
        $spec_file3 = "logo.png"
        $spec_file4 = "failed_login.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}