rule PK_Spotify_ak47 : Spotify
{
    meta:
        description = "Phishing Kit impersonating Spotify"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2024-04-30"
        comment = "Phishing Kit - Spotify - 'From: Ak47.BUlLETS'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "asass"
        $spec_dir2 = "assets"
        $spec_file1 = "4.php"
        $spec_file2 = "Loading4.html"
        $spec_file3 = "fi.html"
        $spec_file4 = "photo_2022-10-10_20-11-05.jpg"
        $spec_file5 = "Spotify.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $zip_file and 
       all of ($spec_dir*) and 
	   all of ($spec_file*)
}
