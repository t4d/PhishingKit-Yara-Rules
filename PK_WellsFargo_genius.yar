rule PK_WellsFargo_genius : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-13"
        comment = "Phishing Kit - Wells Fargo - '!Genius231_Legend+ !"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "index.htm"
        $spec_file2 = "iBass.php"
        $spec_file3 = "SLim.php"
        $spec_file4 = "wewewe.htm"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}