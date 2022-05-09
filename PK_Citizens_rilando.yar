rule PK_Citizens_rilando : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-06"
        comment = "Phishing Kit - CitizensBank - '-  PAGE Made #By RILANDO, WORK HARD DREAM B!G -'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "styless"
        $spec_dir2 = "autob"
        // specific files found in PhishingKit
        $spec_file1 = "Suspended.php"
        $spec_file2 = "valnet.php"
        $spec_file3 = "folnetval.php"
        $spec_file4 = "config.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}