rule APT_serbia_novispy_android_accesibilityservice {
    meta:
        description = "Rule for Serbian NoviSpy Android spyware APK, com.accesibilityservice version"
        author = "Donncha O Cearbhaill, Amnesty International"
        sample = "99673ce7f10e938ed73ed4a99930fbd6499983caa7a2c1b9e3f0e0bb0a5df602"

    strings:
        $dex = { 64 65 78 0A 30 33 ?? 00 }

        // C2 communication
        $c2_1 = "195.178.51.251"
        $c2_2 = "79.101.110.108"
        $c2_3 = "188.93.127.34"

        // Unique Strings
        $u_1 = "kataklinger vibercajzna" ascii nocase
        $u_2 = "select action_command.* from action_command where action_id = ? and trigger_type = ?" ascii nocase
        $u_3 = "6FDF20EAFA2D58AF609C72AE7092BB45" ascii nocase
        $u_4 = "{\"cellChangeMonitoring\":true,\"signalStrengthMonitoring\":true,\"temperatureDelta\":1," ascii nocase
        $u_5 = "{\"fileUpload\":false,\"audioRecording\":false,\"cellChangeMonitoring\":true,"ascii nocase
        $u_6 = "\"serverIp\":\"188.93.127.34\"" ascii nocase
        $u_7 = "ucitavanjepodataka" ascii nocase

        // Other strings
        $s_1 = "test.dat" ascii
        $s_2 = "/active.config" ascii
        $s_3 = "message_map.ser" ascii
        $s_4 = "event type =" ascii
        $s_5 = "change type subtree" ascii
        $s_6 = "change type content description" ascii
        $s_7 = "change type pane title" ascii
        $s_8 = "content change type pane_appeared" ascii
        $s_9 = "window state changed" ascii
        $s_10 = "notification state changed" ascii
        $s_11 = "window content changed" ascii
        $s_12 = "view scrolled" ascii
        $s_13 = "type selection changed" ascii
        $s_14 = "type announcement" ascii
        $s_15 = "scroll position =" ascii
        $s_16 = "imei=%s;imsi=%s;phone=%s;sim_serial=%s;os=%s"
        $s_17 = "imei=%s;imsi=%s;phone=%s;sim_serial=%s;roaming=%s;os=%s"
        $s_18 = "last message = %s, level = %d, hash = %s, node count = %d"
        $s_19 = "MyAccessibilityService"

    condition:
        $dex at 0 and (
          any of ($u*) or
          any of ($c2*) or
          7 of ($s*)
        )
  }


rule APT_serbia_novispy_android_serv_services  {
    meta:
        description = "Rule for Serbian NoviSpy Android spyware APK, com.serv.services version"
        author = "Donncha O Cearbhaill, Amnesty International"
        sample = "087fc1217c897033425fe7f1f12b913cd48918c875e99c25bdb9e1ffcf80f57e"

    strings:
        $dex = { 64 65 78 0A 30 33 ?? 00 }

        // C2 communication
        $c2_comm_1 = "178.220.122.57"

        // Unique Strings


        // C2 commands received via SMS
        $sms_c2_cmd_1 = "C_ARF" ascii
        $sms_c2_cmd_2 = "C_ARN" ascii
        $sms_c2_cmd_3 = "C_AWF" ascii
        $sms_c2_cmd_4 = "C_AWI" ascii
        $sms_c2_cmd_5 = "C_AWN" ascii
        $sms_c2_cmd_6 = "C_CRF" ascii
        $sms_c2_cmd_7 = "C_CRN" ascii
        $sms_c2_cmd_8 = "C_LCW" ascii
        $sms_c2_cmd_9 = "C_MNS" ascii
        $sms_c2_cmd_10 = "C_MXS" ascii
        $sms_c2_cmd_11 = "C_R_F" ascii
        $sms_c2_cmd_12 = "C_R_N" ascii
        $sms_c2_cmd_13 = "C_SMF" ascii
        $sms_c2_cmd_14 = "C_SMN" ascii
        $sms_c2_cmd_15 = "C_SWF" ascii
        $sms_c2_cmd_16 = "C_SWN" ascii
        $sms_c2_cmd_17 = "C_UIR" ascii
        $sms_c2_cmd_18 = "C_UMF" ascii
        $sms_c2_cmd_19 = "C_UMN" ascii
        $sms_c2_cmd_20 = "C_UWF" ascii
        $sms_c2_cmd_21 = "C_UWN" ascii
        $sms_c2_cmd_22 = "C_WLF" ascii
        $sms_c2_cmd_23 = "C_WLN" ascii

        // C2 commands received via FTP.
        // This is not a comprehensive list of commands, generic command names are excluded to prevent false positives.
        $ftp_c2_cmd_1 = "CALL_REC_OFF" ascii
        $ftp_c2_cmd_2 = "CALL_REC_ON" ascii
        $ftp_c2_cmd_3 = "CHARGING_REC_OFF" ascii
        $ftp_c2_cmd_4 = "CHARGING_REC_ON" ascii
        $ftp_c2_cmd_5 = "SECURE_REC_OFF" ascii
        $ftp_c2_cmd_6 = "SECURE_REC_ON" ascii
        $ftp_c2_cmd_7 = "SSD_MOBILE_OFF" ascii
        $ftp_c2_cmd_8 = "SSD_MOBILE_ON" ascii
        $ftp_c2_cmd_9 = "SSD_WIFI_OFF" ascii
        $ftp_c2_cmd_10 = "SSD_WIFI_ON" ascii
        $ftp_c2_cmd_11 = "UPLOAD_INTERVAL" ascii
        $ftp_c2_cmd_12 = "UPLOAD_MOBILE_OFF" ascii
        $ftp_c2_cmd_13 = "UPLOAD_MOBILE_ON" ascii
        $ftp_c2_cmd_14 = "UPLOAD_WIFI_OFF" ascii
        $ftp_c2_cmd_15 = "UPLOAD_WIFI_ON" ascii
        $ftp_c2_cmd_16 = "AUTO_WIFI_INTERVAL" ascii
        $ftp_c2_cmd_17 = "WIFI_LOCK_ON" ascii
        $ftp_c2_cmd_18 = "WIFI_LOCK_OFF" ascii
        $ftp_c2_cmd_19 = "AUTO_WIFI_ON" ascii
        $ftp_c2_cmd_20 = "AUTO_WIFI_OFF" ascii
        $ftp_c2_cmd_21 = "START_AUDIO" ascii

        // App local settings configured based on C2 commands.
        $setting_1 = "UIR" ascii
        $setting_2 = "ULW" ascii
        $setting_3 = "ULM" ascii
        $setting_4 = "SSW" ascii
        $setting_5 = "SSM" ascii
        $setting_6 = "CRN" ascii
        $setting_7 = "SRN" ascii
        $setting_8 = "CRC" ascii
        $setting_9 = "MXS" ascii
        $setting_10 = "MNS" ascii
        $setting_11 = "AWF" ascii
        $setting_12 = "AWI" ascii
        $setting_13 = "CHR" ascii
        $setting_14 = "WLS" ascii
        $setting_15 = "A_R_N" ascii
        $setting_16 = "A_R_F" ascii
        $setting_17 = "U_I" ascii
        $setting_18 = "U_W_N" ascii
        $setting_19 = "S_W_N" ascii
        $setting_20 = "U_M_F" ascii
        $setting_21 = "S_M_F" ascii
        $setting_22 = "A_W_F" ascii
        $setting_23 = "A_W_I" ascii
        $setting_24 = "W_L_N" ascii
        $setting_25 = "C_R_F" ascii
        $setting_26 = "CH_R_F" ascii
        $setting_27 = "S_R_N" ascii

    condition:
        $dex at 0 and (
          any of ($c2_comm*) or
          20 of ($sms_c2_cmd*) or
          20 of ($ftp_c2_cmd*) or
          20 of ($setting*)
        )
}