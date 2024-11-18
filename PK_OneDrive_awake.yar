rule PK_OneDrive_awake : OneDrive
{
    meta:
        description = "Phishing Kit impersonating OneDrive"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://www.stalkphish.com"
        date = "2024-11-17"
        comment = "Phishing Kit - OneDrive - 'Awake | Offiice 365'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "home"
        $spec_dir2 = "ojomu"
        $spec_dir3 = "gmail2_files"
        $spec_file = "AA1.htm"
        $spec_file2 = "YY1.php"
        $spec_file3 = "db.php"
	    $spec_file4 = "gg11.php"
        $spec_file5 = "LL1.png"
        $spec_file6 = "omo101.ico"
        $spec_file7 = "which3.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and 
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
