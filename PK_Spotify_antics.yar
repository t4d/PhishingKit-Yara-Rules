rule PK_Spotify_antics : Spotify
{
    meta:
        description = "Phishing Kit impersonating Spotify"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2024-06-13"
        comment = "Phishing Kit - Spotify - use antics.php file"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "info"
        $spec_dir2 = "Account"
        $spec_file1 = "challenge.php"
        $spec_file2 = "conifglall.php"
        $spec_file3 = "antics.php"
        $spec_file4 = "id.php"
        $spec_file5 = "Spotify.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $zip_file and 
       all of ($spec_dir*) and 
	   all of ($spec_file*)
}
