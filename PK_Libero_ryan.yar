rule PK_Libero_ryan : Libero
{
    meta:
        description = "Phishing Kit impersonating Libero Italy"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-09-04"
        comment = "Phishing Kit - Libero - 'rYan@LIBERO.IT 2023 UPDATE LOGIN INFO'"
rYan@LIBERO.IT 2023 UPDATE LOGIN INFO
    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "files"
        // specific file found in PhishingKit
        $spec_file = "get_pass.php"
        $spec_file2 = "signin.php"
        $spec_file3 = "core-it.js"
        $spec_file4 = "logo-buonissimo.png"
        $spec_file5 = "libero_favicon.ico"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of ($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
