rule PK_Spotify_genius : Spotify
{
    meta:
        description = "Phishing Kit impersonating Spotify"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-08-20"
        comment = "Phishing Kit - Spotify - 'genius'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_dir = "spttf"
        $spec_dir2 = "ico"
        $spec_file1 = "spotico.ico"
        $spec_file2 = "bl5968144.png"
        $spec_file3 = "genius8.php"
        $spec_file4 = "chk.php"
        $spec_file5 = "bankapp.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
       all of ($spec_dir*) and 
	   all of ($spec_file*)
}
