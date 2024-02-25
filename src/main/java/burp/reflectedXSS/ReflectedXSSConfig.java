package burp.reflectedXSS;

import burp.IBurpExtenderCallbacks;
import burp.utils.ConfigUI;
import burp.utils.Utils;
import org.json.JSONObject;
import org.json.JSONTokener;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import static burp.utils.Utils.jFileChooserUtil;

public class ReflectedXSSConfig extends JFrame implements ActionListener {
    private final IBurpExtenderCallbacks callbacks;
    private final ReflectedXSSTable httpListTable;
    private final ReflectedXSSParameterTable parameterTable;
    private String configPath = "";
    final JButton button;
    final PrintWriter stdout;
    private JPanel configPane;
    private JTextField configFileTextField;
    private ReflectedXSSConfigModel conf_list;
    private JCheckBox mime_hide_onoff;
    private JTextField mime_hide_field;
    private JCheckBox hide_0_onoff;
    private JCheckBox show_file_extension_onoff;
    private JTextField show_file_extension_field;
    private JCheckBox hide_file_extension_onoff;
    private JTextField hide_file_extension_field;
    private JCheckBox hide_undetected;
    private JCheckBox hide_path;
    private JCheckBox hide_param_name;
    private JCheckBox under_size_onoff;
    private JTextField under_size_field;

    public ReflectedXSSConfig(IBurpExtenderCallbacks callbacks, ReflectedXSSTable httpListTable, ReflectedXSSParameterTable parameterTable) {
        /*
         * 설정 값이 저장되는 위치: Project.json - 버프 프로젝트 옵션만 저장됨
         * 익스텐션설정 저장 함수 : 익스텐션 설정 값이 저장되지만 파일로 관리할 수 없음
         * -> 설정 저장 시 익스텐션 설정 저장 함수 및 별도 json 함수를 통해 Project.json에 저장한 후
         * -> 설정 로드 시 익스텐션 설정 저장 --> Project.json 순으로 설정을 읽어들임
         * -> 둘다 없으면 Empty
         */
        stdout = new PrintWriter(callbacks.getStdout(), true);
        this.httpListTable = httpListTable;
        this.parameterTable = parameterTable;
        this.callbacks = callbacks;

        // load_rule(false);
        // 기본 설정으로 시작
        conf_list = new ReflectedXSSConfigModel();
        conf_list.setValue(false, false, "JSON",false, "jsp,asp,php", false, "jpg,png,css", false, true, true, true, "30000");

        /* 설정된 Filter에 따라 진단 테이블 List Filter */
        set_table_filter();

        // Config Button 연결
        button = new JButton();
        button.addActionListener(this);

        // UI 생성
        generate_config_ui();
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        /*
         * 설정된 Config File이 없을 시 ConfigUI 호출
         */
        String configPath = callbacks.loadExtensionSetting("Rusist_Config_Path");
        if (configPath == null || configPath.isBlank()) {
            new ConfigUI(callbacks, configPath);
            return;
        }

        /* 설정 버튼 클릭 시 호출 */
        load_rule();    // 진단 Rule Load

        /* 설정 값에 따른 설정 창 value 표시 */
        configFileTextField.setText(configPath);    // 설정 파일 Path

        // Filter 영역 Value 설정
        hide_0_onoff.setSelected(conf_list.hide_0);
        hide_undetected.setSelected(conf_list.hide_undetected);
        hide_path.setSelected(conf_list.hide_path);
        hide_param_name.setSelected(conf_list.hide_param_name);
        under_size_onoff.setSelected(conf_list.under_size_onoff);
        under_size_field.setText(conf_list.under_size);
        show_file_extension_onoff.setSelected(conf_list.show_only_onoff);
        show_file_extension_field.setText(conf_list.show_only_file_ext);
        hide_file_extension_onoff.setSelected(conf_list.hide_onoff);
        hide_file_extension_field.setText(conf_list.hide_file_ext);

        Point mouse_location = MouseInfo.getPointerInfo().getLocation();
        setBounds(mouse_location.x-100, mouse_location.y, 700, 280);    // 마우스 포인터 위치에 창 Open, 창 width, 창 height 설정
        setVisible(true);   // Jframe 이 보이기 위해 필요
    }

    boolean load_rule() {
        /* 탐지 Rule Load */
        configPath = callbacks.loadExtensionSetting("Rusist_Config_Path");
        File conf_file;
        if (configPath != null && !configPath.isBlank()) {
            conf_file = new File(configPath);
        } else {
            return false;
        }
        if(!conf_file.exists()) {
            return false;
        }
//        stdout.println("Rule 파일 내용:");

        // .json 파일 READ
        JSONObject rule_json;
        try {
            JSONObject allConfig = new JSONObject(new JSONTokener(new FileReader(conf_file)));
            if(allConfig.has("ReflectedXSS")) {
                rule_json = allConfig.getJSONObject("ReflectedXSS");
            } else {
                // 설정된 Rule이 없음 -> Default Rule
                // 기본 Rule Setting
                stdout.println("- ReflectedXSS: 설정이 없습니다. 기본 설정을 적용합니다.");
                conf_list.setValue(false, false, "JSON",false, "jsp,asp,php", false, "jpg,png,css", false, true, true, true, "30000");
                return true;
            }
        } catch (FileNotFoundException e) {
            stdout.println("- ReflectedXSS: 설정이 없습니다. 기본 설정을 적용합니다.");
            // 기본 Rule Setting
            conf_list.setValue(false, false, "JSON",false, "jsp,asp,php", false, "jpg,png,css", false, true, true, true, "30000");
            return true;
        }

        /*
         * 설정 값 적용
         */
        conf_list = new ReflectedXSSConfigModel();
        JSONObject rule;
        boolean hide_0_count = (rule_json.has("hide_0_count") && rule_json.getBoolean("hide_0_count"));
        boolean hide_undetected = (rule_json.has("hide_undetected") && rule_json.getBoolean("hide_undetected"));
        boolean hide_path = (rule_json.has("hide_path") && rule_json.getBoolean("hide_path"));
        boolean hide_param_name = (rule_json.has("hide_param_name") && rule_json.getBoolean("hide_param_name"));

        String hide_mime_type = "JSON";
        boolean mime_hide_onoff = false;
        try {
            rule = rule_json.getJSONObject("hide_mime");
            hide_mime_type = rule.getString("hide_mime_types");
            mime_hide_onoff = rule.getBoolean("onoff");
        } catch (Exception ignored) {}

        String hide_files = "";
        boolean hide_onoff = false;
        try {
            rule = rule_json.getJSONObject("hide");
            hide_files = rule.getString("hide_files");
            hide_onoff = rule.getBoolean("onoff");
        } catch (Exception ignored) {}

        String show_files = "";
        boolean show_onoff = false;
        try {
            rule = rule_json.getJSONObject("show_only");
            show_files = rule.getString("show_only_files");
            show_onoff = rule.getBoolean("onoff");
        } catch (Exception ignored) {}

        String under_size = "3000";
        boolean under_onoff = false;
        try {
            rule = rule_json.getJSONObject("under_size");
            under_size = Integer.toString(rule.getInt("size"));
            under_onoff = rule.getBoolean("onoff");
        } catch (Exception ignored) {}

        conf_list.setValue(hide_0_count, mime_hide_onoff, hide_mime_type, show_onoff, show_files, hide_onoff, hide_files,
                hide_undetected, hide_path, hide_param_name, under_onoff,under_size);

        // Config 버튼 텍스트 초기화
        set_conf_button_text();

        /* 설정된 Filter에 따라 진단 테이블 List Filter */
        set_table_filter();

        return true;
    }

//    boolean load_rule() {
//        /* 탐지 Rule Load */
//        configPath = callbacks.loadExtensionSetting("Rusist_Config_Path");
//        File conf_file = null;
//        if (configPath != null) {
//            conf_file = new File(configPath);
//        }
//        if(configPath == null || !conf_file.exists()) {
//            if(true){
//                configPath = jFileChooserUtil(null); // 설정파일 호출
//                configFileTextField.setText(configPath);
//                // 설정 파일 Path 버프에 저장
//                callbacks.saveExtensionSetting("Rusist_Config_Path", configPath);
//            } else {
//                configPath = "";     // 설정 파일 호출 안함(Class 최초 Load 시)
//            }
//        }
////        stdout.println("Rule 파일 내용:");
//        // .json 파일 READ
//        JSONObject rule_json = null;
//        try {
//            JSONObject jsonFile = (JSONObject) new JSONParser().parse(new FileReader(configPath));
//            JSONObject wallru_setting;
//            if(jsonFile.containsKey("WallRu")) {
//                wallru_setting = (JSONObject) jsonFile.get("WallRu");
//                if(wallru_setting.containsKey("ReflectedXSS")){
//                    rule_json = (JSONObject) wallru_setting.get("ReflectedXSS");
//                }
//            }
//        }  catch (FileNotFoundException e) {
//            stdout.println("- Reflected XSS: 설정 파일을 찾을 수 없습니다. Rudin Assist 탭에서 설정 파일을 지정해주세요.");
//        } catch (IOException | ParseException e) {
//            stdout.println("Rule 파일 호출 중 오류 발생");
//            stdout.println("Config Path: " + configPath);
//            stdout.println(e);
//        }
//
//        conf_list = new ReflectedXSSConfigModel();
//        if(rule_json == null || rule_json.isEmpty()) {
//            // 설정된 Rule이 없음 -> Default Rule
//            conf_list.setValue(false, false, "JSON",false, "jsp,asp,php", false, "jpg,png,css", false, true, true, true, "30000");
//        } else {
//            JSONObject under_size = (JSONObject) rule_json.get("under_size");
//            JSONObject hide_mime_rule = (JSONObject) rule_json.get("hide_mime");
//            JSONObject show_only_rule = (JSONObject) rule_json.get("show_only");
//            JSONObject hide_rule = (JSONObject) rule_json.get("hide");
//            conf_list.setValue(
//                    (Boolean) rule_json.get("hide_0_count"),
//                    (Boolean) hide_mime_rule.get("onoff"),
//                    hide_mime_rule.get("hide_mime_types").toString(),
//                    (Boolean) show_only_rule.get("onoff"),
//                    show_only_rule.get("show_only_files").toString(),
//                    (Boolean) hide_rule.get("onoff"),
//                    hide_rule.get("hide_files").toString(),
//                    (Boolean) rule_json.get("hide_undetected"),
//                    (Boolean) rule_json.get("hide_path"),
//                    (Boolean) rule_json.get("hide_param_name"),
//                    (Boolean) under_size.get("onoff"),
//                    under_size.get("size").toString()
//            );
//        }
//        return false;
//    }

    private void generate_config_ui() {
        /* Config 창 - Content 설정 */
        configPane = new JPanel();
        configPane.setLayout(new BoxLayout(configPane, BoxLayout.Y_AXIS));

        /* 설정 파일 위치 Layout */
        Box configPathBox = Box.createHorizontalBox();
        configPathBox.setMaximumSize(new Dimension(10000,50));
        configPathBox.add(Box.createHorizontalStrut(5));  // spacing between button
        configPathBox.add(new JLabel("config_path:"));
        configFileTextField = new JTextField(configPath,50);
        Border configPathLine = BorderFactory.createTitledBorder(" Config 파일 Path ");   // 테두리
        configPathBox.setBorder(configPathLine);
        configPathBox.add(Box.createHorizontalStrut(5));  // spacing between button
        configPathBox.add(configFileTextField);
        
        // 설정 파일 Input 버튼
        JButton config_path_button = new JButton("설정 파일");
        config_path_button.addActionListener(e -> {
            configPath = jFileChooserUtil(configPath); // 설정파일 호출
            configFileTextField.setText(configPath);
        });
        configPathBox.add(Box.createHorizontalStrut(10));  // spacing between button
        configPathBox.add(config_path_button);

        // 설정 파일 위치 Input 행 추가
        configPane.add(configPathBox);

        /* 설정 추가 Layout */
        Box addRuleBox = Box.createVerticalBox();
        addRuleBox.setMinimumSize(new Dimension(50000,300));
        Border addRuleLine = BorderFactory.createTitledBorder(" Filter 설정 "); // 테두리
        addRuleBox.setBorder(addRuleLine);

        // Rule 추가
        // 점검 결과 0인 히스토리 숨김
        Box checkbox_layer = Box.createHorizontalBox();
        checkbox_layer.setMaximumSize(new Dimension(10000,25));
        checkbox_layer.setAlignmentX(Component.LEFT_ALIGNMENT);
        hide_0_onoff = new JCheckBox();
        hide_0_onoff.setSelected(conf_list.hide_0);
        JLabel hide_0_label = new JLabel("Hide 0 count");
        checkbox_layer.add(hide_0_onoff);
        checkbox_layer.add(Box.createHorizontalStrut(5));  // spacing between button
        checkbox_layer.add(hide_0_label);
        addRuleBox.add(checkbox_layer);

        checkbox_layer.add(Box.createHorizontalStrut(10));  // spacing between button

        // Paramter Table - 발견하지 못한 파라미터 숨김
        hide_undetected = new JCheckBox();
        hide_undetected.setSelected(conf_list.hide_undetected);
        JLabel undetected_label = new JLabel("Hide Undetected");
        checkbox_layer.add(hide_undetected);
        checkbox_layer.add(Box.createHorizontalStrut(5));  // spacing between button
        checkbox_layer.add(undetected_label);
//        addRuleBox.add(undetected_box);

        checkbox_layer.add(Box.createHorizontalStrut(10));  // spacing between button

        // Paramter Table - Path 탐지 숨김(Path를 쓰는 Site / 안 쓰는 Site 구분)
        hide_path = new JCheckBox();
        hide_path.setSelected(conf_list.hide_path);
        JLabel hide_path_label = new JLabel("Hide Path");
        checkbox_layer.add(hide_path);
        checkbox_layer.add(Box.createHorizontalStrut(5));  // spacing between button
        checkbox_layer.add(hide_path_label);

        checkbox_layer.add(Box.createHorizontalStrut(10));  // spacing between button

        // Paramter Table - Parameter Name 탐지 숨김
        hide_param_name = new JCheckBox();
        hide_param_name.setSelected(conf_list.hide_param_name);
        JLabel hide_param_name_label = new JLabel("Hide Param Name");
        checkbox_layer.add(hide_param_name);
        checkbox_layer.add(Box.createHorizontalStrut(5));  // spacing between button
        checkbox_layer.add(hide_param_name_label);

        // Response 크기 필터
        Box under_resp_size_Box = Box.createHorizontalBox();
        under_resp_size_Box.setMaximumSize(new Dimension(10000,25));
        under_resp_size_Box.setAlignmentX(Component.LEFT_ALIGNMENT);
        under_size_onoff = new JCheckBox();
        under_size_onoff.setSelected(conf_list.under_size_onoff);
        JLabel under_size_label = new JLabel("[Response Size] Show <");
        under_size_field = new JTextField(conf_list.under_size, 40);
        under_resp_size_Box.add(under_size_onoff);
        under_resp_size_Box.add(Box.createHorizontalStrut(5));  // spacing between button
        under_resp_size_Box.add(under_size_label);
        under_resp_size_Box.add(Box.createHorizontalStrut(10));  // spacing between button
        under_resp_size_Box.add(under_size_field);
        addRuleBox.add(under_resp_size_Box);

        // MIME type hide 필터
        Box hide_mime_type_Box = Box.createHorizontalBox();
        hide_mime_type_Box.setMaximumSize(new Dimension(10000,25));
        hide_mime_type_Box.setAlignmentX(Component.LEFT_ALIGNMENT);
        mime_hide_onoff = new JCheckBox();
        mime_hide_onoff.setSelected(conf_list.mime_hide_onoff);
        JLabel hide_mime_type_label = new JLabel("[MIME Type filter] Hide:");
        mime_hide_field = new JTextField(conf_list.hide_mime_type, 40);
        hide_mime_type_Box.add(mime_hide_onoff);
        hide_mime_type_Box.add(Box.createHorizontalStrut(5));  // spacing between button
        hide_mime_type_Box.add(hide_mime_type_label);
        hide_mime_type_Box.add(Box.createHorizontalStrut(10));  // spacing between button
        hide_mime_type_Box.add(mime_hide_field);
        addRuleBox.add(hide_mime_type_Box);

        // 파일 확장자 필터: show only
        Box show_file_extension_Box = Box.createHorizontalBox();
        show_file_extension_Box.setMaximumSize(new Dimension(10000,25));
        show_file_extension_Box.setAlignmentX(Component.LEFT_ALIGNMENT);
        show_file_extension_onoff = new JCheckBox();
        show_file_extension_onoff.setSelected(conf_list.show_only_onoff);
        JLabel show_file_extension_label = new JLabel("[File filter] Show only:");
        show_file_extension_field = new JTextField(conf_list.show_only_file_ext, 50);
        show_file_extension_Box.add(show_file_extension_onoff);
        show_file_extension_Box.add(Box.createHorizontalStrut(5));  // spacing between button
        show_file_extension_Box.add(show_file_extension_label);
        show_file_extension_Box.add(Box.createHorizontalStrut(10));  // spacing between button
        show_file_extension_Box.add(show_file_extension_field);
        addRuleBox.add(show_file_extension_Box);

        // 파일 확장자 필터: hide
        Box hide_file_extension_Box = Box.createHorizontalBox();
        hide_file_extension_Box.setMaximumSize(new Dimension(10000,25));
        hide_file_extension_Box.setAlignmentX(Component.LEFT_ALIGNMENT);
        hide_file_extension_onoff = new JCheckBox();
        hide_file_extension_onoff.setSelected(conf_list.hide_onoff);
        JLabel hide_file_extension_label = new JLabel("[File filter] Hide:");
        hide_file_extension_field = new JTextField(conf_list.hide_file_ext, 50);
        hide_file_extension_Box.add(hide_file_extension_onoff);
        hide_file_extension_Box.add(Box.createHorizontalStrut(5));  // spacing between button
        hide_file_extension_Box.add(hide_file_extension_label);
        hide_file_extension_Box.add(Box.createHorizontalStrut(10));  // spacing between button
        hide_file_extension_Box.add(hide_file_extension_field);
        addRuleBox.add(hide_file_extension_Box);

        // Show only Check Box 클릭 설정: Show only: true > Hide: false
        show_file_extension_onoff.addActionListener(e -> {
            if(show_file_extension_onoff.isSelected()){
                hide_file_extension_onoff.setSelected(false);
            }
        });

        // Hide Check Box 클릭 설정: Hide: true > Show only: false
        hide_file_extension_onoff.addActionListener(e -> {
            if(hide_file_extension_onoff.isSelected()){
                show_file_extension_onoff.setSelected(false);
            }
        });
        // Rule 설정 추가
        configPane.add(addRuleBox);

        /* 설정 Cancel, Apply 버튼 */
        set_cancel_apply_button();

        /* JFrame 설정 */
        configPane.setBorder(BorderFactory.createEmptyBorder(0 , 10 , 10 , 10));
        setTitle("Reflected XSS 점검 설정");
        setContentPane(configPane);
        setSize(700,350);

        // Config 버튼 텍스트 초기화
        set_conf_button_text();
    }

    private void set_cancel_apply_button() {
        /* Cacel, Apply 버튼 영역 설정 */
        JPanel buttonPanel = new JPanel();  // 버튼 전체 영역
        buttonPanel.setLayout(new BorderLayout());
        buttonPanel.setMaximumSize(new Dimension(10000, 30));   // Height 고정하려고 만듬, width는 상관없어서 크게 잡음
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5,1,0,1));
//        buttonPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));  // 영역 표시

        Box buttonBox = Box.createHorizontalBox();  // 버튼 그룹 영역

        buttonPanel.add(buttonBox, BorderLayout.EAST);  // 꼭 이렇게 해야 정렬됨 ㅡㅡ
        configPane.add(buttonPanel);    // 버튼 영역 Config UI에 추가

        /* Cancel, Apply 버튼 정의 */
        // Cancel 버튼 정의
        JButton cancel_button = new JButton("Cancel");
        cancel_button.addActionListener(e -> dispose());
        buttonBox.add(cancel_button);

        buttonBox.add(Box.createHorizontalStrut(10));  // spacing between button

        // Apply 버튼 정의
        JButton apply_button = new JButton("Apply");
        apply_button.addActionListener(e -> {
            // Apply 시 전체 설정 값 변경
            // ruleTableModel.testConfList 의 값들이 변경되어 있음(tableModel의 데이터 List)
            conf_list.setValue(
                    hide_0_onoff.isSelected(),
                    mime_hide_onoff.isSelected(),
                    mime_hide_field.getText(),
                    show_file_extension_onoff.isSelected(),
                    show_file_extension_field.getText(),
                    hide_file_extension_onoff.isSelected(),
                    hide_file_extension_field.getText(),
                    hide_undetected.isSelected(),
                    hide_path.isSelected(),
                    hide_param_name.isSelected(),
                    under_size_onoff.isSelected(),
                    under_size_field.getText()
            );

            JSONObject rule_json_object = new JSONObject();
            rule_json_object.put("hide_0_count", hide_0_onoff.isSelected());
            rule_json_object.put("hide_undetected", hide_undetected.isSelected());
            rule_json_object.put("hide_path", hide_path.isSelected());
            rule_json_object.put("hide_param_name", hide_param_name.isSelected());
            JSONObject under_size = new JSONObject();
            under_size.put("onoff", under_size_onoff.isSelected());
            under_size.put("size", under_size_field.getText());
            rule_json_object.put("under_size", under_size);
            JSONObject hide_mime_rule = new JSONObject();
            hide_mime_rule.put("onoff", mime_hide_onoff.isSelected());
            hide_mime_rule.put("hide_mime_types", mime_hide_field.getText());
            rule_json_object.put("hide_mime", hide_mime_rule);
            JSONObject show_only_rule = new JSONObject();
            show_only_rule.put("onoff", show_file_extension_onoff.isSelected());
            show_only_rule.put("show_only_files", show_file_extension_field.getText());
            rule_json_object.put("show_only", show_only_rule);
            JSONObject hide_rule = new JSONObject();
            hide_rule.put("onoff", hide_file_extension_onoff.isSelected());
            hide_rule.put("hide_files", hide_file_extension_field.getText());
            rule_json_object.put("hide", hide_rule);

            String config_file_path = configFileTextField.getText();
            Utils.save_rule(rule_json_object, config_file_path, "ReflectedXSS");

            // 설정 파일 Path 버프에 저장
            callbacks.saveExtensionSetting("Rusist_Config_Path", config_file_path);

            // 메인 화면의 설정 버튼 텍스트 업데이트
            set_conf_button_text();

            dispose();

            /* 설정된 Filter에 따라 진단 테이블 List Filter */
            set_table_filter();
        });
        buttonBox.add(apply_button);
    }

    private void set_table_filter() {
        /* 정의된 내용을 테이블에서 해당하는 컬럼에 정규표현식으로 필터링  */
        List<RowFilter<ReflectedXSSTableModel, Object>> list_filters = new ArrayList<>();
        if(conf_list.hide_0){   // Not Found Result Filter
            list_filters.add(RowFilter.regexFilter("[^0]", 7));  // Column Index 7= Count
        }
        if(conf_list.mime_hide_onoff){  // Response Header Content-Type Filter
            String regex_string = conf_list.hide_mime_type.replaceAll(",", "|");
            list_filters.add(RowFilter.regexFilter("^((?!" + regex_string + ").)*$", 4));  // Column Index 4= Header MIME Type
            list_filters.add(RowFilter.regexFilter("^((?!" + regex_string + ").)*$", 5));  // Column Index 5= Body MIME Type
        }
        if(conf_list.show_only_onoff){  // Show File Extension Filter
            String regex_string = conf_list.show_only_file_ext.replaceAll(",", "|");
            list_filters.add(RowFilter.regexFilter("(" + regex_string + ")", 6));  // Column Index 6= File Extension
        }
        if(conf_list.hide_onoff){   // Hide File Extension Filter
            String regex_string = conf_list.hide_file_ext.replaceAll(",", "|");
            list_filters.add(RowFilter.regexFilter("^((?!" + regex_string + ").)*$", 6));  // Column Index 6= File Extension
        }
        if(conf_list.under_size_onoff){ // Response Size Filter
            list_filters.add(RowFilter.numberFilter(RowFilter.ComparisonType.BEFORE, Integer.parseInt(conf_list.under_size), 8));  // Column Index 8= Size
        }
        RowFilter<ReflectedXSSTableModel, Object> rf = RowFilter.andFilter(list_filters);
        httpListTable.sorter.setRowFilter(rf);
        
        /* 탐지된 파라미터 테이블에서 필터(Detected Parameter Table) */
        List<RowFilter<ReflectedXSSParameterTableModel, Object>> param_filters = new ArrayList<>();
        if(conf_list.hide_undetected) {
            param_filters.add(RowFilter.regexFilter("^\\[ Detected (P\\_Name|P\\_Value|Path) \\].*$", 2));
        }
        if(conf_list.hide_param_name) {
            param_filters.add(RowFilter.regexFilter("^(?!\\[ Detected P\\_Name \\]).*$", 2));
        }
        if(conf_list.hide_path) {
            param_filters.add(RowFilter.regexFilter("^(?!\\[Path\\]).*$", 1));
        }
        RowFilter<ReflectedXSSParameterTableModel, Object> param_rf = RowFilter.andFilter(param_filters);
        parameterTable.sorter.setRowFilter(param_rf);
    }

    private void set_conf_button_text() {
        if (conf_list == null || !(conf_list.hide_0 || conf_list.hide_undetected || conf_list.mime_hide_onoff || conf_list.show_only_onoff || conf_list.hide_onoff)){
            button.setText("Rule Config - [현재] Count: 0");
        } else {
            int count = 0;
            String rule_summary = "";
            if(conf_list.hide_0){
                count++;
                rule_summary = "Hide 0 Count";
            }
            if(conf_list.hide_undetected){
                count++;
                rule_summary += rule_summary.isEmpty() ? "Hide Undetected Params" : ", Hide Undetected Params";
            }
            if(conf_list.hide_param_name){
                count++;
                rule_summary += rule_summary.isEmpty() ? "Hide Param Names" : ", Hide Param Names";
            }
            if(conf_list.hide_path){
                count++;
                rule_summary += rule_summary.isEmpty() ? "Hide Path" : ", Hide Path";
            }
            if(conf_list.mime_hide_onoff){
                count++;
                rule_summary += rule_summary.isEmpty() ? "Hide_Type: " : ", Hide_Type: ";
                rule_summary += conf_list.hide_mime_type;
            }
            if(conf_list.show_only_onoff){
                count++;
                rule_summary += rule_summary.isEmpty() ? "Show Ext.: " : ", Show Ext.: ";
                rule_summary += conf_list.show_only_file_ext;
            }
            if(conf_list.hide_onoff){
                count++;
                rule_summary += rule_summary.isEmpty() ? "Hide Ext.: " : ", Hide Ext.: ";
                rule_summary += conf_list.hide_file_ext;
            }
            button.setText("Rule Config || Count: " + count + ", Filters: [" + rule_summary + "]");
        }
    }
}
