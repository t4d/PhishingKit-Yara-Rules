rule PK_Metamask_venza : Metamask
{
    meta:
        description = "Phishing Kit impersonating Metamask"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-09-23"
        comment = "Phishing Kit - Metamask - 'CrEaTeD bY VeNzA'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "images"
        $spec_file1 = "next.php"
        $spec_file2 = "email.php"
        $spec_file3 = "metamask-staging.webflow.css"
        $spec_file4 = "mm-logo.svg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
