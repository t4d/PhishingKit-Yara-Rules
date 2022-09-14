rule PK_Citizens_weebee : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-28"
        comment = "Phishing Kit - CitizensBank - 'From: MrWeeBee'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "settings"
        $spec_dir2 = "process"
        // specific files found in PhishingKit
        $spec_file1 = "emm.php"
        $spec_file2 = "quest.php"
        $spec_file3 = "relogin.php"
        $spec_file4 = "citizen_book.woff"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
