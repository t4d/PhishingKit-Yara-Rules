rule PK_Chase_mody : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-10-11"
        comment = "Phishing Kit - Chase Bank - 'From: Mody@BOA'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Mody"
        // specific files found in PhishingKit
        $spec_file = "mody.php"
        $spec_file1 = "otp.php"
        $spec_file2 = "to2.php"
        $spec_file3 = "email3.php"
        $spec_file4 = "verifymail3.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
