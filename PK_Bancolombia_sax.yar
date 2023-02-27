rule PK_Bancolombia_sax : Bancolombia
{
    meta:
        description = "Phishing Kit impersonating Bancolombia"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2023-02-19"
        comment = "Phishing kit impersonating Bancolombia - use of multiple files named 'sax..."        

    strings:
        // the zipfile working on
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "js"
        $spec_dir1 = "img"
        $spec_file = "sax4.js"
        $spec_file2 = "index4.html"
        $spec_file3 = "login_SVP_BC_zonaB.html"
        $spec_file4 = "icon_font_bc.ttf"
        $spec_file5 = "Banner-osp-softoken-v2.gif"

    condition:
        // look for the ZIP header
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
