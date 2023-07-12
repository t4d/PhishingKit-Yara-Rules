rule PK_Roundcube_rc : Roundcube
{
    meta:
        description = "Phishing Kit impersonating Roundcube login"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-07-07"
        comment = "Phishing Kit - Roundcube - '$_user | RC'"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific file found in PhishingKit
        $spec_file = "roundcube.html"
        $spec_file2 = "roundcube.php"
        $spec_file3 = "port.php"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        // check for file
        all of ($spec_file*)
}
