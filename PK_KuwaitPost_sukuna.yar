rule PK_KuwaitPost_sukuna : KuwaitPost
{
    meta:
        description = "Phishing Kit impersonating Kuwait Post"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-28"
        comment = "Phishing Kit - KFCU - 'From: SUKUNA46'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "settings"
        $spec_dir2 = "process"
        $spec_dir3 = "ses"
        // specific files found in PhishingKit
        $spec_file = "bdelhwayjek.php"
        $spec_file2 = "kw.php"
        $spec_file3 = "c.php"
        $spec_file4 = "load4.php"
        $spec_file5 = "BENEFIT_logo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
