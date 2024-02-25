package burp.authcheck;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class AuthCheckMain extends JPanel implements IMessageEditorController{
    /*
       불충분한 인증(세션 없이 접근) 테스트
       Guest도 세션을 가지고 있는 경우를 고려해야하지 않을 까 싶다.
       Algorithm:
       1. 정상 HTTP Request 획득
       2. Cookie / Authentication Header 삭제
       3. 정상 HTTP Response와 Invalid HTTP Response 비교
       4. 다른 부분 Colorful
       5. Table에는 O/X 로 일치/불일치 여부 표시
     */
    /**
     * Java Swing 구조 때문에 Controller UI를 합침
     * 구시대 유물이라 그런지 Controller 개념 보다는
     * UI에서 Control 하는 개념인 듯
     */
    private final IExtensionHelpers helpers;    // HTTP Data 처리 라이브러리
    IMessageEditor orgRequestViewer;
    IMessageEditor orgResponseViewer;
    IMessageEditor editedRequestViewer;
    IMessageEditor editedResponseViewer;
    IBurpExtenderCallbacks callbacks;

    AuthCheckTableModel tableModel;
    IHttpRequestResponse currentlyDisplayedItem;
    AuthCheckConfig config;

    public AuthCheckMain(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        /* Burp API 연결 */
        this.callbacks = callbacks;
        this.helpers = helpers;

        /* UI 구성: Pane 생성 */
        generate_UI();
    }

    public void addHTTP(boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        /*
         *  HTTP Request, Response Data를 필요한 형태로 정규화한 후, Array에 저장
         *  -> 정규화할 형태 Class 필요, Table Values Array(정규화 Class 형) 필요
         */
        // Threading 안정화를 위해 synchronized() 가 필요할까?
        // PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        if(!messageIsRequest) {
            /* Response 임
             * - Response를 출력해야 Request랑 같이 출력됨
             * - Request는 사용하지 않는 이유:
             *   => Response에 모든 데이터(Request, Response)가 있다보니,
             *      수정해서 재전송한 데이터들을 같은 entry class에 저장이 가능
             *      -> 같은 entry class에 저장이 되야 Origin과 Edited가 1:1 연결이 됨
             */
            List<int[]> orgRequestMarkers = new ArrayList<>();     // requestData 저장용? 잘 모르겠음
            List<int[]> orgResponseMarkers = new ArrayList<>();    // responseData 저장용? 잘 모르겠음

            /* 진단 대상 설정 Load */
            // Test 용 데이터임, 추후 설정 파일에서 불러오도록 해야함

            /* ------------- 진단 MAIN ------------ */
            IRequestInfo iRequestInfo = helpers.analyzeRequest(messageInfo);
            for(HashMap<String, Object> conf : config.getSession_edit_rules()){
                /* 진단 대상인지 확인: Host 비교 */
                String host_regex = conf.get("host").toString();  // 진단 대상 Host 범위(정규표현식)
                String host = iRequestInfo.getUrl().getHost();  // 현재 HTTP의 Host
                if(host.matches(host_regex) && (boolean) conf.get("onoff")) {  // Rule의 진단 대상인지 확인(Host 비교)
                    // 진단 대상 Host 임

                    /*--------------- 취약점 진단(세션 변조) ---------------*/
                    /* Edited Request Header Build */
                    StringBuilder editedHeader = new StringBuilder();  // StringBuilder.append() is FASTER THAN String + String
                    List<String> headerlist = iRequestInfo.getHeaders();
                    editedHeader.append(headerlist.get(0)).append("\r\n");
                    headerlist.remove(0);   // Method Path HTTP_version 행 제거(Header 인 듯 Header 가 아닌)
                    String session = "";

                    for(String header : headerlist){
                        String[] splited_header = header.split(": ");
                        // 진단 대상 Header 확인
                        if(splited_header[0].equals(conf.get("header"))){
                            // Cookie 일 때와 Custom Header 일 때로 구분
                            if(splited_header[0].equals("Cookie")){
                                // Cookie일 때는 Session을 다시 찾아야함
                                String[] cookies = splited_header[1].split("; ");
                                StringBuilder edited_cookie = new StringBuilder();
                                for(String cookie:cookies){
                                    if(cookie.matches(conf.get("target").toString())){
                                        edited_cookie.append(conf.get("edit")).append("; ");
                                        session = cookie;
                                    } else {
                                        edited_cookie.append(cookie).append("; ");
                                    }
                                }
                                splited_header[1] = edited_cookie.toString();
                            } else {
                                // Custom Header 일 때는 그 행 전체를 Session 으로 판단
                                // 현재 Session 저장
                                session = splited_header[1];

                                /* 진단 대상 Header 변조 */
                                splited_header[1] = splited_header[1].replaceFirst(
                                        conf.get("target").toString(),
                                        conf.get("edit").toString());
                            }
                        }
                        editedHeader.append(splited_header[0]).append(": ").append(splited_header[1]).append("\r\n");
                    }
                    // 아닌 패킷 드랍
                    if(session.isEmpty()) {
                        continue;
                    }

                    /* Edited Request Body Build */
                    String[] splited_request = new String(messageInfo.getRequest()).split("\r\n\r\n");
                    editedHeader.append("\r\n");
                    if(splited_request.length != 1) {   // Body 데이터가 있으면
                        editedHeader.append(splited_request[1]);
                    }

                    /* Send Edited Request and Save Response */
                    // ORIGIN 데이터 저장
                    IHttpRequestResponseWithMarkers orgMessageInfoMarked = callbacks.applyMarkers(messageInfo, orgRequestMarkers, orgResponseMarkers);

                    // Send HTTP Request
                    // 원래 HTTP/2 는 다른 방식이지만 오히려 HTTP/1.1 방식으로 보내는 게 오류가 없음
                    IHttpRequestResponse editedMessageInfo = callbacks.makeHttpRequest(
                            messageInfo.getHttpService(),
                            helpers.stringToBytes(editedHeader.toString())
                    );

                    List<int[]> editedRequestMarkers = new ArrayList<>();     // requestData 저장용
                    List<int[]> editedResponseMarkers = new ArrayList<>();    // responseData 저장용
                    IHttpRequestResponseWithMarkers editedMessageInfoMarked = callbacks.applyMarkers(editedMessageInfo, editedRequestMarkers, editedResponseMarkers);
                    
                    /* Response 비교 */
                    // Response Body 동일 -> 취약, 다름 -> 양호?
                    String orgResponse = new String(orgMessageInfoMarked.getResponse());
                    orgResponse = orgResponse.substring(orgResponse.indexOf("\r\n\r\n")+4);
                    String editedResponse = new String(editedMessageInfoMarked.getResponse());
                    editedResponse = editedResponse.substring(editedResponse.indexOf("\r\n\r\n")+4);

                    String compare_result = "불일치(양호)";
                    if(orgResponse.equals(editedResponse)) {
                        if(orgResponse.isEmpty()){
                            compare_result = "Both_Empty";
                        } else {
                            compare_result = "일치(취약?)";
                        }
                    }

                    /* 결과를 Model에 연결 */
                    tableModel.addData(new AuthCheckEntry(
                            tableModel.authCheckList.size()+1,
                            orgMessageInfoMarked,
                            editedMessageInfoMarked.getRequest(),
                            editedMessageInfoMarked.getResponse(),
                            iRequestInfo.getUrl(),
                            iRequestInfo.getMethod(),
                            session,
                            compare_result,
                            orgResponse.length()
                    ));  // 데이터 추가
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

        /* UI 구성: Pane 생성 */
        // history Table 생성
        tableModel = new AuthCheckTableModel(); // Table 내용 담당
        AuthCheckTable httpListTable = new AuthCheckTable(tableModel, this); // Table 그 자체

        // 진단 Config Pop-up Pane
        config = new AuthCheckConfig(callbacks, httpListTable);
        add(config.button, BorderLayout.NORTH);

        // 스크롤 Pane - Table이 출력되는 곳
        JScrollPane httpListScrollPane = new JScrollPane(httpListTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Main pane 분할
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
//        mainSplitPane.setResizeWeight(0.1f);  // GG 도저히 조절이 안됨
        JSplitPane compareSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        compareSplitPane.setResizeWeight(0.5f);

        mainSplitPane.setLeftComponent(httpListScrollPane); // left가 위쪽이라니
        mainSplitPane.setRightComponent(compareSplitPane);  // right가 아래쪽이라니

        // Tabs with Original request/response viewers
        JTabbedPane orgTab = new JTabbedPane();
        orgRequestViewer = callbacks.createMessageEditor(this, false);
        orgResponseViewer = callbacks.createMessageEditor(this, false);
        orgTab.addTab("Origin Request", orgRequestViewer.getComponent());
        orgTab.addTab("Origin Response", orgResponseViewer.getComponent());

        // Tabs with Modified request/response viewers
        JTabbedPane editedTab = new JTabbedPane();
        editedRequestViewer = callbacks.createMessageEditor(this, false);
        editedResponseViewer = callbacks.createMessageEditor(this, false);
        editedTab.addTab("Edited Request", editedRequestViewer.getComponent());
        editedTab.addTab("Edited Response", editedResponseViewer.getComponent());

        compareSplitPane.setLeftComponent(orgTab);  // 왼쪽은 원본!
        compareSplitPane.setRightComponent(editedTab);// 오른쪽은 세션 지운 거!

        // Tabs with request/response viewers
//        mainSplitPane.setDividerLocation(0.5);    // GG 도저히 조절이 안됨
        compareSplitPane.setDividerLocation(0.5);

        // Customize our UI components, 솔직히 무슨 의민지 모르겠음
        callbacks.customizeUiComponent(config.button);
        callbacks.customizeUiComponent(mainSplitPane);
        callbacks.customizeUiComponent(compareSplitPane);
        callbacks.customizeUiComponent(httpListTable);
        callbacks.customizeUiComponent(httpListScrollPane);
        callbacks.customizeUiComponent(orgTab);
        callbacks.customizeUiComponent(editedTab);

        add(mainSplitPane);
        /* UI 생성 끝 */
    }

    public boolean updateConfig() {
        return config.load_rule();
    }
}
