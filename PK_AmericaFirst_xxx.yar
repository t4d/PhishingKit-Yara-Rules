rule PK_AmericaFirst_xxx : AmericaFirst
{
    meta:
        description = "Phishing Kit impersonating America First Credit Union"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = "https://twitter.com/Stalkphish_io/status/1518240511848550402"
        date = "2022-04-29"
        comment = "Phishing Kit - America First - Base64 encoded pages - actor:'-xXx-'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "audient"
        $spec_dir1 = "libs"
        $spec_file1 = "grabber.php"
        $spec_file2 = "process6.php"
        $spec_file3 = "actions.js"
        $spec_file4 = "indexemsx.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}