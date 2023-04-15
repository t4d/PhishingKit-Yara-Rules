rule PK_UKGov_DVLA : UKGov
{
    meta:
        description = "Phishing Kit impersonating UK Government Gateway"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-03-25"
        comment = "Phishing Kit - UK Gov. - Tax payment"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "fonts"
        // specific file found in PhishingKit
        $spec_file = "doc_5.html"
        $spec_file2 = "_mstr_.php"
        $spec_file3 = "js.php"
        

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        $spec_file and
        $spec_file2 and
        $spec_file3 and
        $spec_dir
}