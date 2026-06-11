rule PK_SPankki_mother : SPankki
{
    meta:
        description = "Phishing Kit impersonating S-Pankki bank"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-06-10"
        comment = "Phishing Kit - S-Pankki - '$m = new Mother'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_dir = "spankki"
        $spec_dir2 = "vics"
        $spec_file1 = "settings.php"
        $spec_file2 = "spy.php"
        $spec_file3 = "mkfile.php"
        $spec_file4 = "app.css"
        $spec_file5 = "bots_log.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
       all of ($spec_dir*) and 
	   all of ($spec_file*)
}
