rule PK_Citizens_zigenare : CitizensBank
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-01-24"
        comment = "Phishing Kit - CitizensBank - 'Zigenare Security Solutions'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file1 = "experimental.php"
        $spec_file2 = "email.php"
        $spec_file3 = "details.php"
        $spec_file4 = "finish.php"
        $spec_file5 = "to.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_file*)
}
