package burp.reflectedXSS;

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ReflectedXSSMain extends JPanel implements IMessageEditorController{
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
    IMessageEditor requestViewer;
    IBurpExtenderCallbacks callbacks;

    ReflectedXSSTableModel httpHistoryModel;
    IHttpRequestResponse currentlyDisplayedItem;
    ReflectedXSSParameterTableModel paramTableModel;
    ReflectedXSSParameterTable parameterTable;
    ReflectedXSSResponse responseViewer;
    ReflectedXSSConfig config;

    public ReflectedXSSMain(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
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
        if(!messageIsRequest) {
            /* Response 임
             * - Response를 출력해야 Request랑 같이 출력됨
             * - Request는 사용하지 않는 이유:
             *   => Response에 모든 데이터(Request, Response)가 있다보니,
             *      수정해서 재전송한 데이터들을 같은 entry class에 저장이 가능
             *      -> 같은 entry class에 저장이 되야 Origin과 Edited가 1:1 연결이 됨
             */

            /*
             * List<int[]> requestMarkers, List<int[]> responseMarkers
             * - IHttpRequestResponseWithMarkers 에서 사용하는 Marker 위치(index)
             * - Intruder, Scanner 등 위치 표시, 하이라이팅에 사용됨(getRequestMarkers / getResponseMarkers)
             * - BUT!!!!!!!! 왜 IMessageEditor 나 ITextEditor에는 하이라이팅이 없는 거지 굉장히 불편해
             *   그래서 이거는 못쓰고 JTextPane 등을 통해 직접 커마해서 만들어야함 그러면 쓸수 있는데
             *   그냥 Entity에 저장해도 될거 같은 기분이 듬
             * - 참고로, IMessageEditorTab은 byte[] content 가 파라미터로 전달되서 이 함수와 데이터 연동이 불가능함
             *   따라서, 거기서는 의미가 없음
             */
            List<int[]> requestMarkers = new ArrayList<>();
            List<int[]> responseMarkers = new ArrayList<>();
            List<String[]> doubted_params = new ArrayList<>();  // 의심되는 값 List
            /*
             * getParameters() -> public interface IParameter
             * Fields:
             * - PARAM_BODY, PARAM_COOKIE, PARAM_JSON, PARAM_MULTIPART_ATTR, PARAM_URL, PARAM_XML, PARAM_XML_ATTR
             * - 다양한 형태의 파라미터를 다 추출하는 듯?
             */
            IRequestInfo request = helpers.analyzeRequest(messageInfo);
            List<IParameter> params = request.getParameters();
            IResponseInfo response = helpers.analyzeResponse(messageInfo.getResponse());   // Response Mame Type 얻기 용

            String response_all = new String(messageInfo.getResponse());
            response_all = response_all.substring(response_all.indexOf("\r\n\r\n")+4);  // HTTP Response Body에서만 검색(그래야 XSS)

            detecting_value("name", params, response_all, responseMarkers, doubted_params);
            detecting_value("value", params, response_all, responseMarkers, doubted_params);
            detecting_path(request.getUrl().getFile().split("\\?")[0], response_all, responseMarkers, doubted_params);

            if(!doubted_params.isEmpty()){
                IHttpRequestResponseWithMarkers messageInfoMarked = callbacks.applyMarkers(messageInfo, requestMarkers, responseMarkers);
                /* 결과를 Model에 연결 */
                // PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
                httpHistoryModel.addData(new ReflectedXSSEntry(
                        httpHistoryModel.reflectedXssList.size()+1,
                        messageInfoMarked,
                        doubted_params,
                        request.getUrl(),
                        request.getMethod(),
                        response.getStatedMimeType(),   // Header Mame Type
                        response.getInferredMimeType(), // Body Mame Type
                        responseMarkers.size(),
                        response_all.length()
                ));  // 데이터 추가
            }
            //--------------- TEST 용 ----------------------
//            IResponseInfo response_info = helpers.analyzeResponse(messageInfo.getResponse());
//
//            PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
//            stdout.println("Response Body Mame: " + response_info.getInferredMimeType() + ", Header Mame: " + response_info.getStatedMimeType());
            //--------------- TEST 용 ----------------------
        }
    }

    private void detecting_path(String url_path, String response, List<int[]> responseMarkers, List<String[]> doubted_params) {
        String[] splited_path = url_path.split("/");

        for(String dict: splited_path){
            if(dict.isEmpty()) {
                continue;
            }
            if(dict.length() > 2) { // 1, 2글자는 HTTP Response에 너무 많이 잡힘
                /* Response에서 parameter 찾기
                 * - 존재하는 곳의 위치를 리스트에 저장한 후, Viewer에서 하이라이팅(강조)
                 * - Response에 URL encoding되는 건 공격 구문도 encoding 되기 때문에 찾을 필요가 없음
                 *  -> Request Parameter만 decoding 해서 확인(Content-Type: text/html;charset=EUC-KR)
                 */
                // Parameter가 Plain Text || URLEncoded 인 경우
                // Extension refected-parameter는 URL en/decoder를 만들어서 쓰던데 차이가 있나...?
                String parameter_value = helpers.urlDecode(dict);
                boolean founded = false;
                for(int search_start = response.indexOf(parameter_value);
                    search_start != -1;
                    search_start = response.indexOf(parameter_value, search_start))
                {
                    responseMarkers.add(new int[] {search_start, search_start + parameter_value.length()});
                    search_start++;
                    founded = true;
                }

                if(founded) {
                    // 취약 의심이 존재함
                    // requestMarkers 는 intruder 에 보낼 때 쓰기 위함이 아닐 까 추측
                    doubted_params.add(new String[]{"[Path] " + url_path, "[ Detected Path ] " + dict, dict});
                }
            } else {
//                requestMarkers.add(new int[] {start_point, end_point});
                // 진단 기준에 미치지 못하지만, 그 이유를 표시하기 위해 저장
                doubted_params.add(new String[]{"[Path] " + url_path, "[ Too Short(<3) ] " + dict, dict});
            }
        }
    }

    private void detecting_value(String target, List<IParameter> params, String response, List<int[]> responseMarkers, List<String[]> doubted_params) {
        boolean is_name = target.equals("name");

        for(IParameter param: params){
            if(param.getType() == IParameter.PARAM_COOKIE) {
                continue;
            }
            String detecting_param;
            String table_param_string = param.getName() + "=" + param.getValue();
//            int start_point;
//            int end_point;
            if(is_name){
                detecting_param = param.getName();
//                start_point = param.getNameStart();
//                end_point = param.getNameEnd();
            } else {
                detecting_param = param.getValue();
//                start_point = param.getValueStart();
//                end_point = param.getValueEnd();
            }
            if(detecting_param.length() > 2) { // 1, 2글자는 HTTP Response에 너무 많이 잡힘
                /* Response에서 parameter 찾기
                 * - 존재하는 곳의 위치를 리스트에 저장한 후, Viewer에서 하이라이팅(강조)
                 * - Response에 URL encoding되는 건 공격 구문도 encoding 되기 때문에 찾을 필요가 없음
                 *  -> Request Parameter만 decoding 해서 확인(Content-Type: text/html;charset=EUC-KR)
                 */
                // Parameter가 Plain Text || URLEncoded 인 경우
                // Extension refected-parameter는 URL en/decoder를 만들어서 쓰던데 차이가 있나...?
                String parameter_value = helpers.urlDecode(detecting_param);
                boolean founded = false;
                for(int search_start = response.indexOf(parameter_value);
                    search_start != -1;
                    search_start = response.indexOf(parameter_value, search_start))
                {
                    responseMarkers.add(new int[] {search_start, search_start + parameter_value.length()});
                    search_start++;
                    founded = true;
                }

                if(founded) {
                    // 취약 의심이 존재함
                    doubted_params.add(new String[]{table_param_string, "[ Detected " + (is_name? "P_Name":"P_Value") + " ] " + detecting_param, detecting_param});
                }
            } else {
                // 진단 기준에 미치지 못하지만, 그 이유를 표시하기 위해 저장
                doubted_params.add(new String[]{
                        table_param_string,
                        detecting_param.isEmpty()? "Is Empty" : "[ Too Short(<3) ] " + detecting_param,
                        detecting_param
                });
            }
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
        removeAll();
        setLayout(new BorderLayout());

        /* UI 구성: Pane 생성 */
        // 추후 탐지된 패킷들을 대상으로
        // 파라미터 변환해서 자동 테스트할 지
        // 설정용 한줄 추가 해야할 듯

        // history Table 생성
        httpHistoryModel = new ReflectedXSSTableModel(); // Table 내용 담당
        ReflectedXSSTable httpListTable = new ReflectedXSSTable(httpHistoryModel, this); // Table 그 자체
//        httpListTable.setEnabled(false);    // Table 수정 Off

        // 스크롤 Pane - Table이 출력되는 곳
        JScrollPane httpListScrollPane = new JScrollPane(httpListTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Main pane 분할
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setResizeWeight(0.5f);
        JSplitPane httpInfoSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        httpInfoSplitPane.setResizeWeight(0.5f);

        mainSplitPane.setLeftComponent(httpListScrollPane); // left가 위쪽이라니
        mainSplitPane.setRightComponent(httpInfoSplitPane);  // right가 아래쪽이라니

        // Tabs with Request Parameter viewers
        paramTableModel = new ReflectedXSSParameterTableModel(); // Table 내용
        parameterTable = new ReflectedXSSParameterTable(paramTableModel, this); // Table 그 자체
        parameterTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane paramTab = new JScrollPane(parameterTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        // Tabs with Modified request/response viewers
        JTabbedPane httpInfoTab = new JTabbedPane();
        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = new ReflectedXSSResponse(helpers);
        httpInfoTab.addTab("Request", requestViewer.getComponent());
        httpInfoTab.addTab("Response", responseViewer.responseMainPanel);

        httpInfoSplitPane.setLeftComponent(paramTab);  // 왼쪽은 파라미터 테이블!
        httpInfoSplitPane.setRightComponent(httpInfoTab);// 오른쪽은 HTTP request, response!

        // Tabs with request/response viewers
//        mainSplitPane.setDividerLocation(0.5);    // GG 도저히 조절이 안됨
        httpInfoSplitPane.setDividerLocation(0.5);

        // 진단 Config Pop-up(new) Frame
        config = new ReflectedXSSConfig(callbacks, httpListTable, parameterTable);
        add(config.button, BorderLayout.NORTH);

        // Customize our UI components, 솔직히 무슨 의민지 모르겠음
        callbacks.customizeUiComponent(config.button);
        callbacks.customizeUiComponent(mainSplitPane);
        callbacks.customizeUiComponent(httpInfoSplitPane);
        callbacks.customizeUiComponent(httpListTable);
        callbacks.customizeUiComponent(httpListScrollPane);
        callbacks.customizeUiComponent(parameterTable);
        callbacks.customizeUiComponent(paramTab);
        callbacks.customizeUiComponent(httpInfoTab);

        add(mainSplitPane);
        /* UI 생성 끝 */
    }

    public boolean updateConfig() {
        return config.load_rule();
    }
}
