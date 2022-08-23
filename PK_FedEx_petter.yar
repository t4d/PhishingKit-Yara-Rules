rule PK_FedEx_petter : FedEx
{
    meta:
        description = "Phishing Kit impersonating FedEx"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-08-22"
        comment = "Phishing Kit - FedEx - '[+] fedex petter FULLZ [+]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "system"
        $spec_dir2 = "fedex"
        // specific file found in PhishingKit
        $spec_file = "confirmed.php"
        $spec_file2 = "jeansms2.php"
        $spec_file3 = "tlgrm.php"
        $spec_file4 = "fdx.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
