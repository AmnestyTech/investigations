rule finspy_linux_installer1 {
    meta:
        description = "Rule for FinSpy Linux installer x86 or x64"
        author = "Etienne Maynier, Amnesty Tech"
        sample = "8aaf886a2a2cd459e65277343bc951a2d23555980eddd73218a5c608e6d2a29c"
    strings:
        $a = "%s/.kde/Autostart" ascii wide nocase
        $b = "%s/.kde4/Autostart" ascii wide nocase
        $c = "dmesg --notime 2>/dev/null | grep -i \"hypervisor detected\" | cut -d ':' -f2" ascii wide nocase
        $d = "g_plauncher" ascii wide nocase
        $e = "g_pinstall_host_location" ascii wide nocase
        $f = "g_pinstall_folder" ascii wide nocase
        $g = "%s/.bash_profile" ascii wide nocase
        $h = "lspci 2>/dev/null | grep -i \"system peripheral\" | grep -i \"virtual\"" ascii wide nocase
        $i = "lspci | grep -i \"system peripheral\" | grep -i \"virtual\"" ascii nocase

    condition:
        7 of them
}

rule finppy_linux_coremodule {
    meta:
        description = "Rule for FinSpy Linux core module x86 or x64"
        author = "Etienne Maynier, Amnesty Tech"
    strings:
        $s1 = "ps auxww | grep -iEe 'bt-scan' | grep -v -e grep" ascii
        $s2 = "ls /sys/class/net/ 2>/dev/null | awk '{printf (\"%s\n\", $1)}' 2>/dev/null" ascii
        $s3 = "cat /sys/class/net/eth?/address 2>/dev/null" ascii
        $s4 = "dmesg --notime 2>/dev/null | grep -i \"cpu\" | grep -i \"virtual\"" ascii
        $s5 = "/etc/hostname-merlin" ascii
        $s6 = "@%02X%X%c%08X.dat" ascii
        $s7 = "%s/.bash_profile1" ascii
        $s8 = "%s/.kde4/share/config" ascii
        $s9 = "ls /dev/disk/by-id/ 2>/dev/null" ascii
        $s10 = "/index.php HTTP/1.1" ascii

    condition:
        uint16(0) == 0x457F and 8 of them
}

rule finspy_linux_installer2 {
    meta:
        description = "Rule for FinSpy Linux installer"
        author = "Etienne Maynier, Amnesty Tech"

    strings:
        $encrypted_conf = { 5? a5 aa ca a6 54 5a ?? a? 5a a5 0a } /* header of configuration files */
        $encrypted_bin_32 = { 7f 0d 45 4c 46 01 02 c2 14 68 03 05 0e } /* header of encrypted bin */
        $encrypted_bin_64 = { 7f 07 45 4c 46 02 01 1e 15 01 8e 03 0e } /* header of encrypted bin */

    condition:
        (uint16(0) == 0x457F or uint16(0) == 0x2123) and (#encrypted_conf > 5 or #encrypted_bin_32 > 5 or #encrypted_bin_64 > 5)
}

rule finspy_macos_installer {
    meta:
        description = "Rule for FinSpy OSX installer"
        author = "Etienne Maynier, Amnesty Tech"

    strings:
        $s1 = "80.bundle.zip" ascii
        $s2 = "AAC.dat" ascii
        $s3 = "arch.zip" ascii
        $s4 = "/Library/LaunchAgents" ascii
        $s5 = "7FC.dat" ascii
        $s6 = "logind.plist" ascii
        $s7 = "org.logind.ctp.archive" ascii
        $s8 = "helper" ascii
        $s9 = "Contents/Resources/7f.bundle/Contents/Resources" ascii

    condition:
        uint16(0) == 0xFACF and 8 of them
}

rule finspy_macos_datapkg {
    meta:
        description = "Rule for FinSpy OSX core module"
        author = "Etienne Maynier, Amnesty Tech"

    strings:
        $s1 = "vlacwjwcefforoxisdryuvbqlxvxt" ascii
        $s2 = "vquyqefxqpwytfuherfvzwaqqyanaddmvquyqefxqpwytfu" ascii
        $s3 = "vsczabsutfuhajffslhlkulomhivwligvscza:" ascii
        $s4 = "ijfrkptshbsurggfqxshpiolwupesxewijfrkptxnj" ascii
        $s5 = "wwsodegezqrtafprejkrytzablizbddgwwsodegezqrtafprejxnj" ascii
        $s6 = "clfggqtyflyspjewoxpodxesnpavcpofclfggqtyflyspjewoxpodxesnpavcpofclfggqtyflyspjewoxpodx" ascii
        $s7 = "mhqxzxdbxsfblsxmidzcribjewzkezujmhqxzxdbxsfblsxmidzcribjewzkezujmh" ascii
        $s8 = "sqpviurrqssxwzrzdwldcanprnsuadyhsqpvixnj" ascii
        $s9 = "zfocytolmylaejykmwphsbchfkfzyadbzfocytolmylaejykmwphsbchfkfzyadbz" ascii
        $s10 = "fehbsdjwmqrdndkskegllpixxabegjrdfehbsdjwmqrdndkske" ascii
        $s11 = "exmycityouezjfdczebdfhqdgt:" ascii
        $s12 = "denueozlbzhqzzdjhxjnjhoadjdsmashdenueozlbzhqzzd" ascii


    condition:
        uint16(0) == 0xFACF and 8 of them
}

rule finspy_android_configinapk : android apkhideconfig finspy {
	meta:
		description = "Detect FinFisher FinSpy configuration in APK file. Probably the original FinSpy version."
		date = "2020/08/05"
		reference = "https://github.com/devio/FinSpy-Tools"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
        warning = "May have some False Positive"

	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

	condition:
		uint32(0) == 0x04034b50 and $re and (#re > 50)
}

rule finspy_android_dexden : android dexhideconfig finspy
{
	meta:
		description = "Detect FinFisher FinSpy configuration in DEX file. Probably a newer FinSpy variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"

	strings:
		$config_1 = { 90 5b fe 00 }
		$config_2 = { 70 37 80 00 }
		$config_3 = { 40 38 80 00 }
		$config_4 = { a0 33 84 }
		$config_5 = { 90 79 84 00 }

	condition:
		uint16(0) == 0x6564 and
		#config_1 >= 2 and
		#config_2 >= 2 and
		#config_3 >= 2 and
		#config_4 >= 2 and
		#config_5 >= 2
}

rule FinSpy_TippyTime: finspyTT {
	meta:
		description = "Detect FinFisher FinSpy 'TippyTime' variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
	strings:
		$config_1 = { 90 5b fe 00 }
		$config_2 = { 70 37 80 00 }
		$config_3 = { 40 38 80 00 }
		$config_4 = { a0 33 84 }
		$config_5 = { 90 79 84 00 }
		$timestamp = { 95 E9 D1 5B }

	condition:
		uint16(0) == 0x6564 and
		$timestamp and
		$config_1 and
		$config_2 and
		$config_3 and
		$config_4 and
		$config_5
}

rule FinSpy_TippyPad: finspyTP
{
	meta:
		description = "Detect FinFisher FinSpy 'TippyPad' variant."
		date = "2020/08/05"
		author = "Esther Onfroy a.k.a U+039b - *@0x39b.fr (https://twitter.com/u039b)"
	strings:
		$pad_1 = "0123456789abcdef"
		$pad_2 = "fedcba9876543210"

	condition:
		uint16(0) == 0x6564 and
		#pad_1 > 50 and
		#pad_2 > 50
}
