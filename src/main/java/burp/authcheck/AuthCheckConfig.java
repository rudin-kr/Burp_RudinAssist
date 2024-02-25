package burp.authcheck;

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
import java.util.HashMap;
import java.util.List;

public class AuthCheckConfig extends JFrame implements ActionListener {
    private final IBurpExtenderCallbacks callbacks;
    private final AuthCheckTable httpListTable;
    private String configPath = "";
    final JButton button;
    final PrintWriter stdout;
    private JPanel configPane;
    private JTextField configFileTextField;
    private AuthCheckConfigTableModel ruleTableModel;
    private AuthCheckConfigTable ruleTable;
    private AuthCheckConfigModel conf_list;
    private JCheckBox show_file_extension_onoff;
    private JTextField show_file_extension_field;
    private JCheckBox hide_file_extension_onoff;
    private JTextField hide_file_extension_field;
    private JCheckBox under_size_onoff;
    private JTextField under_size_field;

    public AuthCheckConfig(IBurpExtenderCallbacks callbacks, AuthCheckTable httpListTable) {
        /*
         * 설정 값이 저장되는 위치: Project.json - 버프 프로젝트 옵션만 저장됨
         * 익스텐션 설정 저장 함수 : 익스텐션 설정 값이 저장되지만 파일로 관리할 수 없음
         * -> 설정 저장 시 익스텐션 설정 저장 함수 및 별도 json 함수를 통해 Project.json에 저장한 후
         * -> 설정 로드 시 익스텐션 설정 저장 --> Project.json 순으로 설정을 읽어들임
         * -> 둘다 없으면 Empty
         */
        stdout = new PrintWriter(callbacks.getStdout(), true);
        this.callbacks = callbacks;
        this.httpListTable = httpListTable;

        // load_rule(false);
        // 기본 설정으로 시작
        conf_list = new AuthCheckConfigModel();
        conf_list.setValue(false, "",false,"", new ArrayList<>(), false, "3000");
        
        /* 설정된 Filter에 따라 진단 테이블 List Filter */
        set_table_filter();

        // Config Button
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
        under_size_onoff.setSelected(conf_list.under_size_onoff);
        under_size_field.setText(conf_list.under_size);
        show_file_extension_onoff.setSelected(conf_list.show_only_onoff);
        show_file_extension_field.setText(conf_list.show_only_file_ext);
        hide_file_extension_onoff.setSelected(conf_list.hide_onoff);
        hide_file_extension_field.setText(conf_list.hide_file_ext);

        ruleTableModel.setData(conf_list.edit_session);  // Table 데이터 초기화, Deep Copy
        Point mouse_location = MouseInfo.getPointerInfo().getLocation();
        setBounds(mouse_location.x-100, mouse_location.y, 800, 550);    // 마우스 포인터 위치에 창 Open
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
            if(allConfig.has("AuthCheck")) {
                rule_json = allConfig.getJSONObject("AuthCheck");
            } else {
                // 설정된 Rule이 없음 -> Default Rule
                // 기본 Rule Setting
                stdout.println("- 불충분한 인증/인가: 설정이 없습니다. 기본 설정을 적용합니다.");
                conf_list.setValue(false, "",false,"", new ArrayList<>(), false, "3000");
                return true;
            }
        } catch (FileNotFoundException e) {
            stdout.println("- 불충분한 인증/인가: 설정이 없습니다. 기본 설정을 적용합니다.");
            // 기본 Rule Setting
            conf_list.setValue(false, "",false,"", new ArrayList<>(), false, "3000");
            return true;
        }
        
        /*
         * 설정 값 적용
         */
        conf_list = new AuthCheckConfigModel();
        List<HashMap<String, Object>> session_edit_rules = new ArrayList<>();
        for (Object o : rule_json.getJSONArray("edit_session")) {
            try {
                JSONObject rule = (JSONObject) o;
                session_edit_rules.add(new HashMap<>() {{
                    put("onoff", rule.getBoolean("onoff"));
                    put("host", rule.getString("host"));
                    put("header", rule.getString("header"));
                    put("target", rule.getString("target"));
                    put("edit", rule.getString("edit"));
                }});
            } catch (Exception ignored) {
                stdout.println("불충분한 인증/인가 - 세션 목록에 잘못된 세션 설정이 있습니다.");
            }
        }

        JSONObject rule;
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

        conf_list.setValue(show_onoff, show_files, hide_onoff, hide_files, session_edit_rules, under_onoff, under_size);

        // 메인 화면의 설정 버튼 텍스트 업데이트
        set_conf_button_text();

        /* 설정된 Filter에 따라 진단 테이블 List Filter */
        set_table_filter();

        return true;
    }

//    void load_rule() {
//        /* 탐지 Rule Load */
//        configPath = callbacks.loadExtensionSetting("Rusist_Config_Path");
//        File conf_file = null;
//        if (configPath != null && !configPath.isBlank()) {
//            conf_file = new File(configPath);
//        }
//        if(configPath == null || !conf_file.exists()) {
//            if(true){
//                configPath = Utils.jFileChooserUtil(null);     // 설정 파일 호출
//                configFileTextField.setText(configPath);
//                // 설정 파일 Path 버프에 저장
//                callbacks.saveExtensionSetting("Rusist_Config_Path", configPath);
//            } else {
//                configPath = "";     // 설정 파일 호출 안함(Class 최초 Load 시)
//            }
//        }
////        stdout.println("Rule 파일 내용:");
//
//        // .json 파일 READ
//        JSONObject rule_json = null;
//        try {
//            JSONObject jsonFile = (JSONObject) new JSONParser().parse(new FileReader(configPath));
//            JSONObject wallru_setting;
//            if(jsonFile.containsKey("WallRu")) {
//                wallru_setting = (JSONObject) jsonFile.get("WallRu");
//                if(wallru_setting.containsKey("AuthCheck")){
//                    rule_json = (JSONObject) wallru_setting.get("AuthCheck");
//                }
//            }
//        } catch (FileNotFoundException e) {
//            stdout.println("- 불충분한 인증/인가: 설정 파일을 찾을 수 없습니다. Rudin Assist 탭에서 설정 파일을 지정해주세요.");
//        } catch (IOException | ParseException e) {
//            stdout.println("Rule 파일 호출 중 오류 발생");
//            stdout.println("Config Path: " + configPath);
//            stdout.println(e);
//        }
//
//        conf_list = new AuthCheckConfigModel();
//        if(rule_json == null || rule_json.isEmpty()){
//            // 설정된 Rule이 없음 -> Default Rule
//            // 기본 Rule Setting
//            conf_list.setValue(false, "",false,"", new ArrayList<>(), false, "3000");
//        } else {
//            List<HashMap<String, Object>> session_edit_rules = new ArrayList<>();
//            for (Object o : (JSONArray) rule_json.get("edit_session")) {
//                JSONObject rule = (JSONObject) o;
//                session_edit_rules.add(new HashMap<>() {{
//                    put("onoff", rule.get("onoff"));
//                    put("host", rule.get("host"));
//                    put("header", rule.get("header"));
//                    put("target", rule.get("target"));
//                    put("edit", rule.get("edit"));
//                }});
//            }
//            JSONObject under_size = (JSONObject) rule_json.get("under_size");
//            JSONObject show_only_rule = (JSONObject) rule_json.get("show_only");
//            JSONObject hide_rule = (JSONObject) rule_json.get("hide");
//            conf_list.setValue(
//                    (Boolean) show_only_rule.get("onoff"),
//                    show_only_rule.get("show_only_files").toString(),
//                    (Boolean) hide_rule.get("onoff"),
//                    hide_rule.get("hide_files").toString(),
//                    session_edit_rules,
//                    (Boolean) under_size.get("onoff"),
//                    under_size.get("size").toString()
//            );
//        }
//    }

    private void generate_config_ui() {
        /* Config 창 - Content 설정 */
        configPane = new JPanel();
        configPane.setLayout(new BoxLayout(configPane, BoxLayout.Y_AXIS));

        /* 설정 파일 위치 Layout */
        Box configPathBox = Box.createHorizontalBox();
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
            configPath = Utils.jFileChooserUtil(configPath);
            configFileTextField.setText(configPath);
        });
        configPathBox.add(Box.createHorizontalStrut(10));  // spacing between button
        configPathBox.add(config_path_button);

        // 설정 파일 위치 Input 행 추가
        configPane.add(configPathBox);

        /* Filter 추가 Layout */
        Box addFilterBox = Box.createVerticalBox();
        addFilterBox.setMinimumSize(new Dimension(50000,100));
        Border addFilterLine = BorderFactory.createTitledBorder(" Filter 설정 "); // 테두리
        addFilterBox.setBorder(addFilterLine);

        // Response 크기 필터
        Box under_resp_size_Box = Box.createHorizontalBox();
        under_resp_size_Box.setMaximumSize(new Dimension(10000,25));
        under_resp_size_Box.setAlignmentX(Component.LEFT_ALIGNMENT);
        under_size_onoff = new JCheckBox();
        under_size_onoff.setSelected(conf_list.under_size_onoff);
        JLabel under_size_label = new JLabel("[Response Size] Show <");
        under_size_field = new JTextField(conf_list.under_size, 50);
        under_resp_size_Box.add(under_size_onoff);
        under_resp_size_Box.add(Box.createHorizontalStrut(5));  // spacing between button
        under_resp_size_Box.add(under_size_label);
        under_resp_size_Box.add(Box.createHorizontalStrut(10));  // spacing between button
        under_resp_size_Box.add(under_size_field);
        addFilterBox.add(under_resp_size_Box);

        // 파일 확장자 필터: Show only
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
        addFilterBox.add(show_file_extension_Box);

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
        addFilterBox.add(hide_file_extension_Box);

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
        // Filter 설정 추가
        configPane.add(addFilterBox);

        /* Rule 추가 Layout */
        Box addRuleBox = Box.createVerticalBox();

        // Rule Input Box, Header UI 귀찮아서 전부 Border로 감쌈
        Box add_rule_input_box = Box.createHorizontalBox();

        String[] header_list = {" Host ", " Header ", " Target ", " Edit "};
        String[] input_box_example = {".*", "Cookie", "JSESSIONID=(.*)", "JSESSIONID=EDITED"};
        JTextField[] rule_input_field = new JTextField[4];
        for(int i = 0; i < 4; i++){
            rule_input_field[i] = new JTextField(input_box_example[i], 20);
            rule_input_field[i].setBorder((BorderFactory.createTitledBorder(header_list[i])));
            add_rule_input_box.add(rule_input_field[i]);
        }
        addRuleBox.add(add_rule_input_box);
        
        // Rule 추가 버튼
        JButton rule_add_button = new JButton("Rule 추가");   // JTextField의 Box 높이 때문인지 높이가 안바뀜 -> 개행도 안됨
        rule_add_button.addActionListener(e -> addTestRule(rule_input_field));
        add_rule_input_box.add(rule_add_button);
        
        // 테두리 추가
        Border addRuleLine = BorderFactory.createTitledBorder(" Rule 추가 "); // 테두리
        addRuleBox.setBorder(addRuleLine);
        configPane.add(addRuleBox);

        /* 설정 파일 내용 Table */
        ruleTableModel = new AuthCheckConfigTableModel();
        ruleTable = new AuthCheckConfigTable(ruleTableModel);
        JScrollPane tableScrollPane = new JScrollPane(ruleTable);
        Border tableLine = BorderFactory.createTitledBorder(" Test Rules ");    // 테두리
        tableScrollPane.setBorder(tableLine);
        configPane.add(tableScrollPane);

        /* 설정 Cancel, Apply 버튼 */
        set_cancel_apply_button();

        /* JFrame 설정 */
        configPane.setBorder(BorderFactory.createEmptyBorder(0 , 10 , 10 , 10));
        setTitle("불충분한 인증 점검 설정");
        setContentPane(configPane);
        setSize(800,500);

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
        cancel_button.addActionListener(e -> config_close());
        buttonBox.add(cancel_button);

        buttonBox.add(Box.createHorizontalStrut(10));  // spacing between button

        // Apply 버튼 정의
        JButton apply_button = new JButton("Apply");
        apply_button.addActionListener(e -> {
            // Apply 시 전체 설정 값 변경
            // ruleTableModel.testConfList 의 값들이 변경되어 있음(tableModel의 데이터 List)
            List<HashMap<String, Object>> session_edit_rules = new ArrayList<>();
            for(HashMap<String, Object> conf: ruleTableModel.getData()){    // 2차원의 경우 반복문을 통해서 원소를 Deep Copy 해야 함...
                HashMap<String, Object> rule = new HashMap<>() {{
                    put("onoff", conf.get("onoff"));
                    put("host", conf.get("host"));
                    put("header", conf.get("header"));
                    put("target", conf.get("target"));
                    put("edit", conf.get("edit"));
                }};
                session_edit_rules.add(rule);
            }
            conf_list.setValue(
                    show_file_extension_onoff.isSelected(),
                    show_file_extension_field.getText(),
                    hide_file_extension_onoff.isSelected(),
                    hide_file_extension_field.getText(),
                    session_edit_rules,
                    under_size_onoff.isSelected(),
                    under_size_field.getText()
            );

            JSONObject rule_json_object = new JSONObject();
            JSONObject under_size = new JSONObject();
            under_size.put("onoff", under_size_onoff.isSelected());
            under_size.put("size", under_size_field.getText());
            rule_json_object.put("under_size", under_size);
            JSONObject show_only_rule = new JSONObject();
            show_only_rule.put("onoff", show_file_extension_onoff.isSelected());
            show_only_rule.put("show_only_files", show_file_extension_field.getText());
            rule_json_object.put("show_only", show_only_rule);
            JSONObject hide_rule = new JSONObject();
            hide_rule.put("onoff", hide_file_extension_onoff.isSelected());
            hide_rule.put("hide_files", hide_file_extension_field.getText());
            rule_json_object.put("hide", hide_rule);
            rule_json_object.put("edit_session", session_edit_rules);

            String config_file_path = configFileTextField.getText();
            Utils.save_rule(rule_json_object, config_file_path, "AuthCheck");

            // 설정 파일 Path 버프에 저장
            callbacks.saveExtensionSetting("Rusist_Config_Path", config_file_path);
            
            // 메인 화면의 설정 버튼 텍스트 업데이트
            set_conf_button_text();

            config_close();

            /* 설정된 Filter에 따라 진단 테이블 List Filter */
            set_table_filter();
        });
        buttonBox.add(apply_button);
    }

    private void set_table_filter() {
        List<RowFilter<AuthCheckTableModel, Object>> filters = new ArrayList<>();
        if(conf_list.under_size_onoff){ // Response Size Filter
            filters.add(RowFilter.numberFilter(RowFilter.ComparisonType.BEFORE, Integer.parseInt(conf_list.under_size), 8));  // Column Index 7= Size
        }
        if(conf_list.show_only_onoff){
            String regex_string = conf_list.show_only_file_ext;
            if(regex_string.contains(",")){
                regex_string = regex_string.replaceAll(",", "\\$|");
            }
            filters.add(RowFilter.regexFilter("(" + regex_string + "$)", 5));  // Column Index 4= File Extension
        }
        if(conf_list.hide_onoff){
            String regex_string = conf_list.hide_file_ext;
            if(regex_string.contains(",")){
                regex_string = regex_string.replaceAll(",", "\\$|");
            }
            filters.add(RowFilter.regexFilter("^((?!" + regex_string + "$).)*$", 5));  // Column Index 4= File Extension
        }
        RowFilter<AuthCheckTableModel, Object> rf = RowFilter.andFilter(filters);
        httpListTable.sorter.setRowFilter(rf);
    }

    private void config_close() {
        /* 수정상태에서 Close 하면 수정한 상태가 취소가 안되기 때문에 Config가 바뀐 줄 오해할 소지가 있어서 추가함 */
        // BUG: https://stackoverflow.com/questions/4490659/why-is-cancelcellediting-not-called-when-pressing-escape-while-editing-a-jtabl
        CellEditor cellEditor = ruleTable.getCellEditor();
        if (cellEditor != null) {
            cellEditor.cancelCellEditing();
        }
        dispose();
    }

    private void set_conf_button_text() {
        // Filter Count
        String filter_summary = null;
        if(conf_list.show_only_onoff){
            filter_summary = "Show_only: [" + conf_list.show_only_file_ext + "]";
        }
        if(conf_list.hide_onoff){   // Show only가 on이면 여기는 무조건 off
            filter_summary = "Hide: [" + conf_list.hide_file_ext + "]";
        }
        if(filter_summary == null){
            filter_summary = "[Filter] None";
        } else {
            filter_summary = "[Filter] " + filter_summary;
        }

        // Session Rule Count
        List<String> config = new ArrayList<>();
        for(HashMap<String, Object> conf: conf_list.edit_session){
            config.add((String) conf.get("target"));
        }
        String session_summary;
        if (conf_list.edit_session == null || conf_list.edit_session.isEmpty()){
            session_summary = "[Rule] Count: 0";
        } else {
            session_summary = "[Rule] Count: " + conf_list.edit_session.size() + ", Rules: " + config;
        }
        button.setText("Rule Config || " + filter_summary + " || " + session_summary);
    }

    private void addTestRule(JTextField[] rule_input_field) {
        ruleTableModel.addData(new HashMap<>(){{
            put("onoff", true);
            put("host", rule_input_field[0].getText());
            put("header", rule_input_field[1].getText());
            put("target", rule_input_field[2].getText());
            put("edit", rule_input_field[3].getText());
        }});
    }

    public List<HashMap<String, Object>> getSession_edit_rules() {
        return conf_list.edit_session;
    }
}
