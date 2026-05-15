rule PK_Alibaba_fake : Alibaba
{
    meta:
        description = "Phishing Kit impersonating Alibaba"
        licence = "AGPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2026-05-01"
        comment = "Phishing Kit - Alibaba - 'Fake message for UX' comment"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_dir2 = "image"
        $spec_file1 = "O1CN018OJRrQ1xSUVFkQK59_!!6000000006442-2-tps-460-400.avif"
        $spec_file2 = "simg_single_icon_favicon.ico"
        $spec_file3 = "submit.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
