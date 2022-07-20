rule PK_Liberbank_metri : Liberbank
{
    meta:
        description = "Phishing Kit impersonating Liberbank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-07-18"
        comment = "Phishing Kit - Liberbank - '$METRI_TOKEN'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "M3tri-hash-bots"
        $spec_dir2 = "LB-files"
        // specific file found in PhishingKit
        $spec_file = "LB-infos.php"
        $spec_file2 = "LB-rd-otp.php"
        $spec_file3 = "liberbank-rzlt.txt"
        $spec_file4 = "visited-ips.txt"
        $spec_file5 = "anti9.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
