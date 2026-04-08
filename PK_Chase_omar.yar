rule PK_Chase_omar : Chase
{
    meta:
        description = "Phishing Kit impersonating Chase bank"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2026-04-08"
        comment = "Phishing Kit - Chase Bank - 'Developed for omarkh5625'"

    strings:
        $local_file = { 50 4b 03 04 }
        $spec_dir = "backups"
        $spec_dir2 = "sections"
        $spec_dir3 = "forms"
        $spec_file = "apiEmailAccessFields.js"
        $spec_file1 = "anitbot.php"
        $spec_file2 = ".aes_key.bin"
        $spec_file3 = "admin.js"
        $spec_file4 = "form_form1.js"
        $spec_file5 = "new_york_night_6.jpg"

    condition:
        uint32(0) == 0x04034b50 and 
	    $local_file and 
	    all of ($spec_dir*) and 
	    all of ($spec_file*)
}
