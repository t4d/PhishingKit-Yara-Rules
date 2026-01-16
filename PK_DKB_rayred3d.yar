rule PK_DKB_rayred3d : DKB
{
    meta:
        description = "Phishing Kit impersonating Das kann Bank (DKB)"
        licence = "AGPL-3.0"
        author = "Thomas Damonneville"
        reference = ""
        date = "2026-01-12"
        comment = "Phishing Kit - DKB - 't.me/RAYRED3D'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "victims"
        $spec_dir2 = "imgs"
        $spec_dir3 = "dkb_2025"
        $spec_file1 = "stuats.json"
        $spec_file2 = "prepros.config"
        $spec_file3 = "DarkNet.jpg"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        all of ($spec_dir*) and
        // check for file
        all of ($spec_file*)
}
