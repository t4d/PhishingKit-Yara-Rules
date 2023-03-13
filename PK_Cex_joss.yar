rule PK_Cex_joss : CEX
{
    meta:
        description = "Phishing Kit impersonating CEX.io"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://lukeleal.com/research/posts/elzero-x-sniper-phishing-kits/"
        date = "2023-03-01"
        comment = "Phishing Kit - CEX.io"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "CEX.IO_files"
        $spec_dir2 = "poto"
        // specific files found in PhishingKit
        $spec_file = "4.php"
        $spec_file2 = "2fa-Code.html"
        $spec_file3 = "Incorrect-Code.html"
        $spec_file4 = "Untitled.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
