package burp.authcheck;

import java.util.HashMap;
import java.util.List;

public class AuthCheckConfigModel {
    Boolean under_size_onoff;
    String under_size;
    Boolean show_only_onoff;
    String show_only_file_ext;
    Boolean hide_onoff;
    String hide_file_ext;
    List<HashMap<String, Object>> edit_session;

    public void setValue(Boolean show_only_onoff, String show_only_files, Boolean hide_onoff, String hide_files, List<HashMap<String, Object>> edit_session, Boolean under_size_onoff, String under_size) {
        this.show_only_onoff = show_only_onoff;
        show_only_file_ext = show_only_files;
        this.hide_onoff = hide_onoff;
        hide_file_ext = hide_files;
        this.edit_session = edit_session;
        this.under_size_onoff = under_size_onoff;
        this.under_size = under_size;
    }
}
