rule PK_PostNord_frag : PostNord
{
    meta:
        description = "Phishing Kit impersonating PostNord.se"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-01-09"
        comment = "Phishing Kit - PostNord - 'FRAG'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "xapp"
        // specific files found in PhishingKit
        $spec_file1 = "indlaeser_.html"
        $spec_file2 = "account.php"
        $spec_file3 = "payment.php"
        $spec_file4 = "embedded-checkout-7f51b6350a.css"


    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
