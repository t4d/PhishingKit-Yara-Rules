rule PK_Coinbase_hadyspeed : Coinbase
{
    meta:
        description = "Phishing Kit impersonating Coinbase"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-02"
        comment = "Phishing Kit - Coinbase - 'COINBASE SCAM PAGE + ADMIN LIVE PANEL V1 BY @HadySpeed'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "2fa"
        $spec_dir2 = "IDentity"
        $spec_dir3 = "signin"
        // specific files found in PhishingKit
        $spec_file1 = "sendbot.php"
        $spec_file2 = "activity.php"
        $spec_file3 = "beep.wav"
        $spec_file4 = "Coinbase - Sign In_files"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
