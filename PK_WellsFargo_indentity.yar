rule PK_WellsFargo_indentity : WellsFargo
{
    meta:
        description = "Phishing Kit impersonating Wells Fargo"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-29"
        comment = "Phishing Kit - Wells Fargo - 'WELLSFARGO ScamPage By GreyHatPakistan' and 'WELLSFARGO Indentity'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "processing"
        $spec_dir2 = "mrknowsall"
        // specific file found in PhishingKit
        $spec_file = "indentity.php"
        $spec_file2 = "ssn&dob.php"
        $spec_file3 = "selfie.php"
        $spec_file4 = "mrknowsall.php"
        $spec_file5 = "wf.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
