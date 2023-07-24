rule PK_OrangeBank_triangle : OrangeBank
{
    meta:
        description = "Phishing Kit impersonating Orange Bank"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-24"
        comment = "Phishing Kit - OrangeBank - with a 'triangle' directory"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        $spec_dir2 = "triangle"
        $spec_dir3 = "svgs"
        // specific file found in PhishingKit
        $spec_file = "IdenREU.php"
        $spec_file2 = "IdenCAC.php"
        $spec_file3 = "AuthSMS.php"
	    $spec_file4 = "oblogo.png"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*) and 
	    all of ($spec_dir*)
}
