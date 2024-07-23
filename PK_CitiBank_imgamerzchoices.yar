rule PK_CitiBank_imgamerzchoices : CitiBank
{
    meta:
        description = "Phishing Kit impersonating Citi Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-07-19"
        comment = "Phishing Kit - Citi - 'This is Citi Bank Scama By @imgamerzchoices On tg'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "index"
        $spec_dir2 = "login"
        $spec_dir3 = "antis"
        // specific files found in PhishingKit
        $spec_file1 = "antifuk.php"
        $spec_file2 = "string.php"
        $spec_file3 = "personal.php"
        $spec_file4 = "vixxxyz5.php"
        $spec_file5 = "citi_logo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}