rule PK_CIC_tche : CIC
{
    meta:
        description = "Phishing Kit impersonating CIC bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-26"
        comment = "Phishing Kit - CIC - 'From: TCHE-Dev<cantact>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Select"
        $spec_dir2 = "auto_system"
        // specific files found in PhishingKit
        $spec_file1 = "data_cle.php"
        $spec_file2 = "data_sms.php"
        $spec_file3 = "cle.js"
        $spec_file4 = "sms.html"
        $spec_file5 = "Select_cleverify.php"
        $spec_file6 = "B-a-internet-securite-bancaire.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
