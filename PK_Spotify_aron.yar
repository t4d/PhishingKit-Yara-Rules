rule PK_Spotify_aron : Spotify
{
    meta:
        description = "Phishing Kit impersonating Spotify"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-29"
        comment = "Phishing Kit - Spotify - 'Scama Spotify v1' by aron-tn"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_dir1 = "ARONXVicTims"
        $spec_dir2 = "ARONXFILES"
        $spec_file1 = "xSND.php"
        $spec_file2 = "XBSEND.php"
        $spec_file3 = "Bxsend.php"
        $spec_file4 = "aron.css"
        $spec_file5 = "spotify.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
       all of ($spec_dir*) and 
	   all of ($spec_file*)
}
