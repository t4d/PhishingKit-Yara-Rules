rule PK_ErsteBank_maxdev : ErsteBank
{
    meta:
        description = "Phishing Kit impersonating Erste Bank (Sparkasse.at) "
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-12-01"
        comment = "Phishing Kit - ErsteBank - '- CrEaTeD bY maxDev -'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "bots"
        $spec_dir2 = "sts"
        // specific file found in PhishingKit
        $spec_file = "George-symbol.svg"
        $spec_file2 = "email.php"
        $spec_file3 = "next.php"
        $spec_file4 = "pass1.php"
        $spec_file5 = "Doppel-Logo_o_Claim.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
