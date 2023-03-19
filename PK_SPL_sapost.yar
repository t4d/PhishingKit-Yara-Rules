rule PK_SPL_sapost : SPL
{
    meta:
        description = "Phishing Kit impersonating SPLonline.com.sa"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-03-17"
        comment = "Phishing Kit - SPL"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "ar"
        $spec_dir2 = "bots"
        // specific files found in PhishingKit
        $spec_file1 = "processing.php"
        $spec_file2 = "smso.php"
        $spec_file3 = "botMother.php"
        $spec_file4 = "md.php"
        $spec_file5 = "ksa-flag.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
