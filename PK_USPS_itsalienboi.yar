rule PK_USPS_itsalienboi : USPS
{
    meta:
        description = "Phishing Kit impersonating USPS"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-07"
        comment = "Phishing Kit - USPS - 'Scama By @itsalienboi' based on XFinity scama"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "1_files"
        $spec_dir2 = "Schedule a Redelivery _ USPS_files"
        // specific file found in PhishingKit
        $spec_file = "bill.php"
        $spec_file2 = "getdata.php"
        $spec_file3 = "mailaccess.php"
        $spec_file4 = "wait.php"
        $spec_file5 = "logo-sb.svg"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
