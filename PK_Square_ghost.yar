rule PK_Square_ghost : Square
{
    meta:
        description = "Phishing Kit impersonating Square"
        licence = "GPL-3.0"
        author = "Thomas 'tAd' Damonneville"
        reference = ""
        date = "2022-04-03"
        comment = "Phishing Kit - Square - 'From: Ghost - Square Login 2 <k1r4@app-crew.id>'"

    strings:
        $zip_file = { 50 4b 03 04 }
        $spec_dir = "assets"
        $spec_file1 = "lojhjfhg587g85g7hfghifg58g7h5h58g.php"
        $spec_file2 = "process2.php"
        $spec_file3 = "sq.png"
        $spec_file4 = "secjhdjrhgyg87g85yg85yuryhfjhgtjbhjfhbjgbhutyb8t8ybughbjgj.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip_file and
        $spec_dir and
        // check for file
        all of ($spec_file*)
}
