rule PK_CitiBank_youngblood : CitiBank
{
    meta:
        description = "Phishing Kit impersonating Citi Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-05-04"
        comment = "Phishing Kit - Citi - '-By @Youngblood1920 \\ KOREAN POWER-'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "account_files"
        $spec_dir2 = "login_files"
        $spec_dir3 = "uploads"
        // specific files found in PhishingKit
        $spec_file1 = "telegram_bot.php"
        $spec_file2 = "card_send.php"
        $spec_file3 = "account_send.php"
        $spec_file4 = "1440_Citi-PLT@3x.png"
        $spec_file5 = "tmobile_submit.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}