rule PK_Spotify_xone : Spotify
{
    meta:
        description = "Phishing Kit impersonating Spotify"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2025-08-26"
        comment = "Phishing Kit - Spotify - 'RootXOne'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        $spec_dir = "xonefiles"
        $spec_dir2 = "sourcexone"
        $spec_file1 = "xonevisa.php"
        $spec_file2 = "xonesecondsmsthankyou.php"
        $spec_file3 = "SELF.php"
        $spec_file4 = "xonemethodpayment.css"
        $spec_file5 = "mastercardverfie.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
           $local_file and 
       all of ($spec_dir*) and 
           all of ($spec_file*)
}
