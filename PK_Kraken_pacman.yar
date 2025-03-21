rule PK_Kraken_pacman : Kraken
{
    meta:
        description = "Phishing Kit impersonating Kraken"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://carlesi.vg/2025/03/20/phishing-against-kraken/"
        date = "2025-03-21"
        comment = "Phishing Kit - Kraken - dev. tests from '/home/sumrqbqz/public_html/kraken/file.php'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "accounts-1r5k4dPhCfkuPxEja3sVC"
        $spec_dir2 = "_next"
        $spec_dir3 = "chunks"
        // specific files found in PhishingKit
        $spec_file = "signin.html"
        $spec_file2 = "file.php"
        $spec_file3 = "53801947e6c69442.css"
        $spec_file4 = "forgot-username-3657770a01048779.js"
        $spec_file5 = "security-shield-light.e75ea770.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
