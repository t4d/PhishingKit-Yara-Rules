rule PK_SummitFCU_prohqcker : SummitFCU
{
    meta:
        description = "Phishing Kit impersonating Summit FCU"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-04-11"
        comment = "Phishing Kit - Summit FCU - '@prohqcker *Summit FCU***'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "css"
        $spec_file1 = "personall.html"
        $spec_file2 = "prohqcker11.php"
        $spec_file3 = "c.html"
        $spec_file4 = "klt7lef.css"
        $spec_file5 = "desktop-logo.png"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
