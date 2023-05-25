rule PK_IRS_prohqcker : IRS
{
    meta:
        description = "Phishing Kit impersonating Internal Revenue Service"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-25"
        comment = "Phishing Kit - ICS - 'From: Prohqcker'"

    strings:
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "js"
        $spec_dir2 = "images"
        // specific files found in PhishingKit
        $spec_file1 = "file.php"
        $spec_file2 = "form.php"
        $spec_file3 = "info.html"
        $spec_file4 = "IRS-Logo.svg"
        $spec_file5 = "tut.html"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and 
        all of ($spec_file*)
}
