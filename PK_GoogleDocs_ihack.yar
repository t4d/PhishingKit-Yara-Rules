rule PK_GoogleDocs_ihack : GoogleDocs
{
    meta:
        description = "Phishing Kit impersonating Google docs"
        licence = "GPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2023-06-22"
        comment = "Phishing Kit - by Ihack"

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        // specific directory found in PhishingKit
        $spec_dir = "google_data"
        $spec_dir2 = "index_files"
        // specific file found in PhishingKit
        $spec_file = "other.php"
        $spec_file2 = "gmail.php"
        $spec_file3 = "aol.php"
        $spec_file4 = "logo-rdc-header.png"
        $spec_file5 = "storage.swf"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        // make sure we have a local file header
        $zip_file and
        all of($spec_dir*) and 
        // check for file
        all of ($spec_file*)
}
