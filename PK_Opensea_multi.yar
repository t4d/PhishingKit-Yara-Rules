rule PK_Opensea_multi : Opensea
{
    meta:
        description = "Phishing Kit impersonating Opensea, targeting Ledger, MetaMask, Crypto.com, Trustwallet, Walletconnect"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-03-11"
        comment = "Phishing Kit - Opensea - 'OPENSEA LOG'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "config"
        $spec_dir2 = "nftdrop"
        $spec_dir3 = "offer"

        $spec_file1 = "wallet.php"
        $spec_file2 = "README-TUTORIAL.txt"
        $spec_file3 = "process.php"
        $spec_file4 = "crawlerdetect.php"
        $spec_file5 = "opensea-white.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
