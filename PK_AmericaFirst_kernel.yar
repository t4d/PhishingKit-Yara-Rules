rule PK_AmericaFirst_kernel : AmericaFirst
{
    meta:
        description = "Phishing Kit impersonating America First Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-11-27"
        comment = "Phishing Kit - America First - 'Kernel American FCU Info'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "kernel"
        $spec_dir1 = "dist"
        $spec_file1 = "question_auth.php"
        $spec_file2 = "core.php"
        $spec_file3 = "buffer.php"
        $spec_file4 = "sus.gif"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
