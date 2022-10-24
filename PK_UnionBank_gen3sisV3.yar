rule PK_UnionBank_gen3sisV3 : UnionBank
{
    meta:
        description = "Phishing Kit impersonating UnionBank"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-10-21"
        comment = "Phishing Kit - UnionBank - '[ + ] Gen3sis V3 [ + ]'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "Union Bank of the Philippines_files"
        // specific file found in PhishingKit
        $spec_file = "idol1.php"
        $spec_file2 = "mobilenumberprocess.php"
        $spec_file3 = "otpprocess.php"
        $spec_file4 = "saved_resource.html"
        $spec_file5 = "KIN.txt"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
