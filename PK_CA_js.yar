rule PK_CA_js : Credit_Agricole
{
    meta:
        description = "Phishing Kit impersonating Credit Agricole"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-07"
        comment = "Phishing Kit - Credit Agricole - full JS kit"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir1 = "config"
        $spec_dir2 = "js"
        $spec_file0 = "init.js"
        $spec_file1 = "4.0ec808a8.js"
        $spec_file2 = "vendor.677b4d5b.css"
        $spec_file3 = "index.html"
        $spec_file4 = "materialdesignicons-webfont.e9db4005.woff2"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
