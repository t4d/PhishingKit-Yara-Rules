rule PK_Comerica_tgreat : ComericaBank
{
    meta:
        description = "Phishing Kit impersonating Comerca Bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-28"
        comment = "Phishing Kit - ComericaBank - 'Telegram ID: @tgreat_coder Commerica Bank'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Sstech"
        $spec_dir2 = "css"
        // specific files found in PhishingKit
        $spec_file = "det1.php"
        $spec_file1 = "otp.css"
        $spec_file2 = "sst9.php"
        $spec_file3 = "redirect2.html"
        $spec_file4 = "comer logo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
