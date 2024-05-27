rule PK_BankOfAmerica_xbalti : BankOfAmerica
{
    meta:
        description = "Phishing Kit impersonating Bank Of America"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-05-13"
        comment = "Phishing Kit - BankOfAmerica - 'BY XBALTI'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "XBALTI"
        $spec_dir2 = "js"
        $spec_dir3 = "my"
        // specific file found in PhishingKit
        $spec_file = "antifuck.php"
        $spec_file2 = "Verification.php"
        $spec_file3 = "send.php"
        $spec_file4 = "BofA_rgb.png"
        $spec_file5 = "XBALTI.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
