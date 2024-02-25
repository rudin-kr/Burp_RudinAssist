package burp.reflectedXSS;

public class ReflectedXSSConfigModel {
    String under_size;
    Boolean under_size_onoff;
    Boolean hide_0;
    Boolean mime_hide_onoff;
    String hide_mime_type;
    Boolean show_only_onoff;
    String show_only_file_ext;
    Boolean hide_onoff;
    String hide_file_ext;
    Boolean hide_undetected;
    Boolean hide_path;
    Boolean hide_param_name;


    public void setValue(Boolean hide_0_result, Boolean mime_hide_onoff, String hide_mime_type, Boolean show_only_onoff, String show_only_files, Boolean hide_onoff, String hide_files, Boolean hide_undetected, Boolean hide_path, Boolean hide_param_name, Boolean under_size_onoff, String under_size) {
        hide_0 = hide_0_result;
        this.mime_hide_onoff = mime_hide_onoff;
        this.hide_mime_type = hide_mime_type;
        this.show_only_onoff = show_only_onoff;
        show_only_file_ext = show_only_files;
        this.hide_onoff = hide_onoff;
        hide_file_ext = hide_files;
        this.hide_undetected = hide_undetected;
        this.hide_path = hide_path;
        this.hide_param_name = hide_param_name;
        this.under_size_onoff = under_size_onoff;
        this.under_size = under_size;
    }
}
