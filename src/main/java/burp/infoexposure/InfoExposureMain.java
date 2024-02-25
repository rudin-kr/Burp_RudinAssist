package burp.infoexposure;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InfoExposureMain extends JPanel implements IMessageEditorController, IMessageEditorTabFactory {
    /**
       중요 정보 노출 진단
       Algorithm:
       1. 정상 HTTP Response 획득
       2. HTTP Response Header, Body에서 Rule에 설정된 정보(정규표현식) 검색
       3. Highlighting
       5. Table에는 노출된 정보 표시?
     */
    /*
     * Java Swing 구조 때문에 Controller UI를 합침
     * 구시대 유물이라 그런지 Controller 개념 보다는
     * UI에서 Control 하는 개념인 듯
     */
    private final IExtensionHelpers helpers;    // HTTP Data 처리 라이브러리
    IMessageEditor requestViewer;
    IMessageEditor responseViewer;
    IBurpExtenderCallbacks callbacks;
    InfoExposureTableModel tableModel;
    IHttpRequestResponse currentlyDisplayedItem;
    InfoExposureConfig config;

    public InfoExposureMain(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        /* Burp API 연결 */
        this.callbacks = callbacks;
        this.helpers = helpers;

        /* IMessageTabFactory 추가 */
        callbacks.registerMessageEditorTabFactory(this);

        /* UI 구성: Pane 생성 */
        generate_UI();
    }

    public void addHTTP(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        /*
         *  HTTP Request, Response Data를 필요한 형태로 정규화한 후, Array에 저장
         *  -> 정규화할 형태 Class 필요, Table Values Array(정규화 Class 형) 필요
         */
        // Threading 안정화를 위해 synchronized() 가 필요할까?
        if(!messageIsRequest) {
            /* Response 임
             * - Response를 출력해야 Request랑 같이 출력됨
             * - Request는 사용하지 않는 이유:
             *   => Response에 모든 데이터(Request, Response)가 있다보니,
             *      수정해서 재전송한 데이터들을 같은 entry class에 저장이 가능
             *      -> 같은 entry class에 저장이 되야 Origin과 Edited가 1:1 연결이 됨
             */
            List<int[]> requestMarkers = new ArrayList<>();     // requestData 저장용? 잘 모르겠음
            List<int[]> responseMarkers = new ArrayList<>();    // responseData 저장용? 잘 모르겠음

            /* 진단 대상 설정 Load */
            // Test 용 데이터임, 추후 설정 파일에서 불러오도록 해야함

            /* ------------- 진단 MAIN ------------ */
            IRequestInfo iRequestInfo = helpers.analyzeRequest(messageInfo);
            for(HashMap<String, Object> conf : config.getDetecting_patterns()){
                /* 진단 대상인지 확인: Host 비교 */
                String host_regex = conf.get("host").toString();  // 진단 대상 Host 범위(정규표현식)
                String host = iRequestInfo.getUrl().getHost();  // 현재 HTTP의 Host
                if(host.matches(host_regex) && (boolean) conf.get("onoff")) {  // Rule의 진단 대상인지 확인(Host 비교)
                    // 진단 대상 Host 임

                    /*--------------- 취약점 진단(정보 노출) ---------------*/
                    /* HTTP Response의 모든 데이터(Header, Body)에서 정규표현식 검색 */
                    // ORIGIN 데이터 저장
                    IHttpRequestResponseWithMarkers messageInfoMarked = callbacks.applyMarkers(messageInfo, requestMarkers, responseMarkers);
                    String response = new String(messageInfoMarked.getResponse());
                    Pattern rule = Pattern.compile(conf.get("pattern").toString());
                    Matcher search = rule.matcher(response);

                    StringBuilder find_result = new StringBuilder();
                    int count = 0;
                    if(search.find()){
                        find_result.append(search.group());
                        count++;
                        while(search.find()){
                            find_result.append(", ").append(search.group());
                            count++;
                        }

                        /* 결과를 Model에 연결 */
                        tableModel.addData(new InfoExposureEntry(
                                tableModel.infoExposureList.size()+1,
                                messageInfoMarked,
                                iRequestInfo.getUrl(),
                                iRequestInfo.getMethod(),
                                conf.get("pattern").toString(),
                                find_result,
                                count,
                                response.length()
                        ));  // 데이터 추가
                    }
                }
            }
            //--------------- TEST 용 ----------------------
//            IResponseInfo response = helpers.analyzeResponse(messageInfo.getResponse());
//
//            PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
            //--------------- TEST 용 ----------------------
        }
    }

    /*
     * implement IMessageEditorController
     * this allows our request/response viewers to obtain details about the messages being displayed
     */
    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    private void generate_UI() {
        this.removeAll();
        this.setLayout(new BorderLayout());

        /* UI 구성: Config Frame 생성 */
        // 탐지 List Table 생성
        tableModel = new InfoExposureTableModel(); // Table 내용 담당
        InfoExposureTable httpListTable = new InfoExposureTable(tableModel, this); // Table 그 자체

        // 진단 Config Pop-up(new) Frame
        config = new InfoExposureConfig(callbacks, httpListTable);
        add(config.button, BorderLayout.NORTH);

        // 스크롤 Pane - Table이 출력되는 곳
        JScrollPane httpListScrollPane = new JScrollPane(httpListTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        /* UI 구역 분할 */
        // Main pane 분할
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
//        mainSplitPane.setResizeWeight(0.1f);  // GG 도저히 조절이 안됨
        JSplitPane httpSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        httpSplitPane.setResizeWeight(0.5f);

        mainSplitPane.setLeftComponent(httpListScrollPane); // left가 위쪽이라니
        mainSplitPane.setRightComponent(httpSplitPane);  // right가 아래쪽이라니

        /* 하단 HTTP Viewer 생성 */
        // Tabs with Request viewers
        JTabbedPane reqTab = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(this,false);
        reqTab.addTab("Request", requestViewer.getComponent());

        // Tabs with Response viewers
        JTabbedPane resTab = new JTabbedPane();
        responseViewer = callbacks.createMessageEditor(this,false);
        resTab.addTab("Response", responseViewer.getComponent());

        httpSplitPane.setLeftComponent(reqTab);  // 왼쪽은 Request!
        httpSplitPane.setRightComponent(resTab);// 오른쪽은 Response!

        // Tabs with request/response viewers
//        mainSplitPane.setDividerLocation(0.5);    // GG 도저히 조절이 안됨
        httpSplitPane.setDividerLocation(0.5);

        // Customize our UI components, 솔직히 무슨 의민지 모르겠음
        callbacks.customizeUiComponent(config.button);
        callbacks.customizeUiComponent(mainSplitPane);
        callbacks.customizeUiComponent(httpSplitPane);
        callbacks.customizeUiComponent(httpListTable);
        callbacks.customizeUiComponent(httpListScrollPane);
        callbacks.customizeUiComponent(reqTab);
        callbacks.customizeUiComponent(resTab);

        add(mainSplitPane);
        /* UI 생성 끝 */
    }

    /*
     * implements IMessageEditorTabFactory
     */
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new InfoExposureEditorTab(helpers, config);
    }

    public boolean updateConfig() {
        return config.load_rule();
    }
}
