package burp.reflectedXSS;

import burp.IExtensionHelpers;
import burp.utils.TextLineNumber;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultHighlighter;
import javax.swing.text.Highlighter;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ReflectedXSSResponse extends JTextArea {
    /*  Response View
    *   Response Message 출력
    * */

    private final Highlighter highlighter;
    private final IExtensionHelpers helpers;
//    private final PrintWriter stdout;
    final JPanel responseMainPanel;
    final JScrollPane responseDataPane;
    private JTextField searchField;
    private JLabel match_text;
    private String search_text = "";
    private HashMap<String, ArrayList<Integer>> text_location_list;
    private int cur_location_index;
    private int param_matches_count;

    public ReflectedXSSResponse(IExtensionHelpers helpers) {
        this.helpers = helpers;
//        stdout = new PrintWriter(callbacks.getStdout(), true);
        setEditable(false);
        setWrapStyleWord(true);
        setLineWrap(true);
        getCaret().setVisible(true);
        getCaret().setSelectionVisible(true);
        setCaretColor(Color.GREEN);
        responseDataPane = new JScrollPane(this);

//        float[] hsbColor = Color.RGBtoHSB(43,43,43,null);
//        stdout.println("hsbColor: " + hsbColor[0] + ", " + hsbColor[1] + ", " + hsbColor[2]);
        setBackground(Color.getHSBColor(0f, 0f, 0.17f));

        TextLineNumber tln = new TextLineNumber(this);    // Line Number 추가
        responseDataPane.setRowHeaderView( tln );

        highlighter = getHighlighter();

        /* Response UI 구성 */
        responseMainPanel = new JPanel();
        responseMainPanel.setLayout(new BoxLayout(responseMainPanel, BoxLayout.Y_AXIS));
        responseMainPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        Box dataBox = Box.createHorizontalBox();
        dataBox.add(responseDataPane);
        Box searchBox = Box.createHorizontalBox();

        searchBox.setMaximumSize(new Dimension(5000, 10));
        searchBox.setBorder(BorderFactory.createEmptyBorder(5,10,5,10));
        createSearchBar(searchBox);

        responseMainPanel.add(dataBox);
        responseMainPanel.add(searchBox);
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
//            stdout.println("Search Text: " + searchField.getText() + ", direction: " + direction);
            // 검색어가 변경됨, 모든 값을 초기화
            search_text = searchField.getText();
            text_location_list = new HashMap<>();
            // 이전 검색 결과 Highlight 제거
            Highlighter.Highlight[] highlight_list = highlighter.getHighlights();
            for(int i = param_matches_count; i < highlight_list.length; i++){
                highlighter.removeHighlight(highlight_list[i]);
            }

            int text_position = 0;
            String contents = getText();    // 좀 이상하지만 처음에 만들 때 이 Class는 JTextArea 였음;; 구조 다시 짜야하지만 귀찮은 관계로...
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

        setCaretPosition(text_location_list.get(search_text).get(cur_location_index));
    }

    public void setMessage(byte[] responseData, List<String[]> doubted_params) {
        String contents = helpers.bytesToString(responseData);
        setText(contents);

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
        for(String[] param : doubted_params) {
            // IMessageEditorTab에 추가하면서 Host를 추출하기 어려워 pattern만 확인
            if(!param[1].contains("Detected")) {
                continue;
            }
            Pattern rule = Pattern.compile(param[2]);
            Matcher search = rule.matcher(contents);
            String find_result;
            int start_point = 0;

            while(search.find(start_point)){
                find_result = search.group();
                start_point = contents.indexOf(find_result, start_point);
//                    float[] hsbColor = Color.RGBtoHSB(176,138,248,null);
//                    stdout.println("hsbColor: " + hsbColor[0] + ", " + hsbColor[1] + ", " + hsbColor[2]);
                DefaultHighlighter.DefaultHighlightPainter painter = new DefaultHighlighter.DefaultHighlightPainter(Color.getHSBColor(0.67f, 0.55f, 0.48f));
                try {
                    highlighter.addHighlight(start_point, start_point + find_result.length(), painter);
                    start_point++;
                } catch (BadLocationException ignored) { }
            }
            setCaretPosition(start_point);
            param_matches_count = highlighter.getHighlights().length;
        }

    }
}
