rule PK_Citizens_wealthmint : Citizens
{
    meta:
        description = "Phishing Kit impersonating Citizens Bank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-06-28"
        comment = "Phishing Kit - Citizens - '- @wealthmint -' AKA 'RD267'"

    strings:
        // the zipfile working on
        $local_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "css"
        $spec_dir2 = "images"
        // specific files found in PhishingKit
        $spec_file1 = "next.php"
        $spec_file2 = "quest.html"
        $spec_file3 = "CTZ_Green-01.png"
        $spec_file4 = "citizensns.min.42588.css"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and 
	   $local_file and 
	   all of ($spec_dir*) and 
	   all of ($spec_file*)
}
