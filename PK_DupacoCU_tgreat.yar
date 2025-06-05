rule PK_DupacoCU_tgreat : DupacoCU
{
    meta:
        description = "Phishing Kit impersonating Dupaco Community Credit Union"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-05-28"
        comment = "Phishing Kit - DupacoCU - 'Telegram ID: @tgreat_coder DUPACO CU'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Sstech"
        $spec_dir2 = "css"
        // specific files found in PhishingKit
        $spec_file = "det3.php"
        $spec_file1 = "otp.html"
        $spec_file2 = "sst9.php"
        $spec_file3 = "details.html"
        $spec_file4 = "dupaco.PNG"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
