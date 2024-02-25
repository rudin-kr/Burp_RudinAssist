package burp.infoexposure;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IMessageEditorTab;
import burp.utils.TextLineNumber;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InfoExposureEditorTab implements IMessageEditorTab {
    private final IExtensionHelpers helpers;
    private final InfoExposureConfig config;

    private byte[] content;
    private JTextArea editorBody;
    private Highlighter highlighter;
    private JTextField searchField;
    private JLabel match_text;
    private String search_text = "";
    private HashMap<String, ArrayList<Integer>> text_location_list;
    private int param_matches_count;
    private int cur_location_index;
    private JPanel editorMainPanel;

    public InfoExposureEditorTab(IExtensionHelpers helpers, InfoExposureConfig config) {
        this.helpers = helpers;
        this.config = config;
        generate_UI();
    }

    @Override
    public String getTabCaption() {
        return "정보 노출";
    }

    @Override
    public Component getUiComponent() {
        return editorMainPanel;
    }

    @Override   // Tab 표시 여부 -> true: Tab 표시, false: Tab 미표시
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return true;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.content = content;
        String str_content = helpers.bytesToString(content);
        editorBody.setText(str_content);

        /* Search Bar 관련 값 초기화 */
        search_text = "";
        cur_location_index = 0;
        searchField.setText("Search linear Text(Enter: Next, Shift + Enter: Before)");
        text_location_list = new HashMap<>();
        match_text.setText("0 matches");
        // 이전 검색 결과 Highlight 제거
        Highlighter.Highlight[] highlight_list = highlighter.getHighlights();
        for(int i = param_matches_count; i < highlight_list.length; i++){
            highlighter.removeHighlight(highlight_list[i]);
        }

        /* 노출된 정보 검색 및 표시(하이라이트) */
        for(HashMap<String, Object> conf : config.getDetecting_patterns()) {
            // IMessageEditorTab에 추가하면서 Host를 추출하기 어려워 pattern만 확인
            if((boolean) conf.get("onoff")) {
                Pattern rule = Pattern.compile(conf.get("pattern").toString());
                Matcher search = rule.matcher(str_content);
                String find_result;
                int start_point = 0;

                while(search.find(start_point)){
                    find_result = search.group();
                    start_point = str_content.indexOf(find_result, start_point);
//                    float[] hsbColor = Color.RGBtoHSB(176,138,248,null);
//                    stdout.println("hsbColor: " + hsbColor[0] + ", " + hsbColor[1] + ", " + hsbColor[2]);
                    DefaultHighlighter.DefaultHighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.getHSBColor(0.67f, 0.55f, 0.48f));
                    try {
                        highlighter.addHighlight(start_point, start_point + find_result.length(), painter);
                        start_point++;
                    } catch (BadLocationException ignored) { }
                }
                editorBody.setCaretPosition(start_point);
                param_matches_count = highlighter.getHighlights().length;
            }
        }
    }

    @Override   // 출력하는데 딱히 의미 없음, 어디서 쓰는 지 모르겠음
    public byte[] getMessage() {
        return content;
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return new byte[0];
    }

    private void generate_UI() {
        editorBody = new JTextArea();
        editorBody.setEditable(false);
        editorBody.setWrapStyleWord(true);
        editorBody.setLineWrap(true);
        editorBody.getCaret().setVisible(true);
        editorBody.getCaret().setSelectionVisible(true);
        editorBody.setCaretColor(Color.GREEN);
        editorBody.setBackground(Color.getHSBColor(0f, 0f, 0.17f));

        JScrollPane infoExposureContainer = new JScrollPane(editorBody);
        TextLineNumber tln = new TextLineNumber(editorBody);    // Line Number 추가
        infoExposureContainer.setRowHeaderView( tln );

        highlighter = editorBody.getHighlighter();

        /* EditorTab 전체 UI 구성 */
        editorMainPanel = new JPanel();
        editorMainPanel.setLayout(new BoxLayout(editorMainPanel, BoxLayout.Y_AXIS));
        editorMainPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        Box dataBox = Box.createHorizontalBox();
        dataBox.add(infoExposureContainer);
        Box searchBox = Box.createHorizontalBox();

        searchBox.setMaximumSize(new Dimension(5000, 10));
        searchBox.setBorder(BorderFactory.createEmptyBorder(5,10,5,10));
        createSearchBar(searchBox);

        editorMainPanel.add(dataBox);
        editorMainPanel.add(searchBox);
    }

    private void createSearchBar(Box searchBox) {
        searchField = new JTextField("Search linear Text(Enter: Next, Shift + Enter: Before)", 50);
        // Enter Key 입력 시 검색
        searchField.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyCode() == KeyEvent.VK_ENTER){
                    if(e.isShiftDown()) {
                        search_text("before");
                    } else {
                        search_text("next");
                    }
                }
            }
        });
        JButton searchBeforeButton = new JButton("<");
        JButton searchNextButton = new JButton(">");
        match_text = new JLabel("0 matches");

        searchBox.add(searchBeforeButton);
        searchBox.add(Box.createHorizontalStrut(5));  // spacing
        searchBox.add(searchNextButton);
        searchBox.add(Box.createHorizontalStrut(10));  // spacing
        searchBox.add(searchField);
        searchBox.add(Box.createHorizontalStrut(10));  // spacing
        searchBox.add(match_text);

        // 검색기능 구현
        searchBeforeButton.addActionListener(e -> search_text("before"));
        searchNextButton.addActionListener(e -> search_text("next"));
    }

    private void search_text(String direction) {
        ArrayList<Integer> location_list;
        if (!search_text.equals(searchField.getText())) {
            // 검색어가 변경됨, 모든 값을 초기화
            search_text = searchField.getText();
            text_location_list = new HashMap<>();
            // 이전 검색 결과 Highlight 제거
            Highlighter.Highlight[] highlight_list = highlighter.getHighlights();
            for(int i = param_matches_count; i < highlight_list.length; i++){
                highlighter.removeHighlight(highlight_list[i]);
            }

            int text_position = 0;
            String contents = editorBody.getText();
            location_list = new ArrayList<>();
            while (true) {
                text_position = contents.indexOf(search_text, text_position);
                if (text_position == -1) {
                    break;
                }
//                float[] hsbColor = Color.RGBtoHSB(21,32,85,null);
//                stdout.println("hsbColor: " + hsbColor[0] + ", " + hsbColor[1] + ", " + hsbColor[2]);
                // 뭔가 하이라이트 tag 변수 List로 관리해야할 듯, location_list 형태를 바꿔서 추가하자
                location_list.add(text_position);
                DefaultHighlighter.DefaultHighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.getHSBColor(0.64f, 0.75f, 0.33f));
                try {
                    highlighter.addHighlight(text_position, text_position + search_text.length(), painter);
                    text_position++;
                } catch (BadLocationException ignored) {
                }
            }
            text_location_list.put(search_text, location_list);
            cur_location_index = 0;
            match_text.setText(location_list.size() + " matches");
        } else {
            // 검색어는 동일, 이전/다음 위치로 이동
            location_list = text_location_list.get(search_text);
            if (direction.equals("next")) {
                cur_location_index = ++cur_location_index % location_list.size();
            } else {
                if(cur_location_index == 0){
                    cur_location_index = location_list.size() - 1;
                } else {
                    cur_location_index--;
                }
            }
        }

        editorBody.setCaretPosition(text_location_list.get(search_text).get(cur_location_index));
    }
}
