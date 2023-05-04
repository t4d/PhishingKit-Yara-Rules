rule PK_Spotify_zabi : Spotify
{
    meta:
        description = "Phishing Kit impersonating Spotify"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-03"
        comment = "Phishing Kit - Spotify - using a 'zabi.php' file"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific files found in PhishingKit
        $spec_file1 = "indecator.svg"
        $spec_file2 = "nem.html"
        $spec_file3 = "indlaeser_.html"
        $spec_file4 = "zabi.php"
        $spec_file5 = "spotify.svg"
        $spec_file6 = "otpsms.php"
        $spec_file7 = "details.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_file*)
}
