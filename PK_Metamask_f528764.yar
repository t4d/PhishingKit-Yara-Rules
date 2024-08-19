rule PK_Metamask_f528764 : Metamask
{
    meta:
        description = "Phishing Kit impersonating Metamask"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-14"
        comment = "Phishing Kit - Metamask - using f528764 named directory"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "MT"
        $spec_dir2 = "f528764"
        $spec_file1 = "Wallet.html"
        $spec_file2 = "Info.html"
        $spec_file3 = "ad.php"
        $spec_file4 = "send_Phrase.php"
        $spec_file5 = "mm-close-black.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
