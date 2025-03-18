rule PK_Caixa_db : Caixa
{
    meta:
        description = "Phishing Kit impersonating Caixa Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-03-18"
        comment = "Phishing Kit - Caixa Bank - usinng database to store data"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "personal-banking"
        $spec_dir1 = "installation"
        $spec_file1 = "kyc-approval.php"
        $spec_file2 = "bills.php"
        $spec_file3 = "currency.php"
        $spec_file4 = "owl.video.play.png"
        $spec_file5 = "onlinebanking.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
