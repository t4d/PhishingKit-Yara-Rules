rule PK_SocieteGenerale_m3tri : SocieteGenerale
{
    meta:
        description = "Phishing Kit impersonating Societe Generale"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-05-15"
        comment = "Phishing Kit - Societe Generale - '/== SG LOG By METRI==/'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_dir = "M3tri-hash-bots"
        $spec_dir1 = "visites"
        $spec_dir2 = "sass"
        $spec_file1 = "OTP.php"
        $spec_file2 = "logOtp.php"
        $spec_file3 = "PORT.php"
        $spec_file4 = "RD.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
