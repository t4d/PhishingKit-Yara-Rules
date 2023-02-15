rule PK_Blockchain_tg : Blockchain
{
    meta:
        description = "Phishing Kit impersonating Blockchain.com"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-13"
        comment = "Phishing Kit - Blockchain.com - Telegram exfiltration"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "api.php"
        $spec_file2 = "login.html"
        $spec_file3 = "telegram.php"
        $spec_file4 = "blockchainwallet-c96153e854a3020571ca.js"
        $spec_file5 = "wallet-borrow-sm.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
