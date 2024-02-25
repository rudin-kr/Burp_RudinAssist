package burp;

import burp.authcheck.AuthCheckMain;
import burp.infoexposure.InfoExposureMain;
import burp.reflectedXSS.ReflectedXSSMain;
import burp.utils.ConfigUI;

import javax.swing.*;
import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IHttpListener
{
    // Burp API imports
    IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    AuthCheckMain authCheckPanel;
    InfoExposureMain infoExposurePanel;
    ReflectedXSSMain reflectedXSSPanel;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        //Callback Objects
        this.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("Rudin Assistant - Web vuln check");

        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);

        // obtain our output stream
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        // Extender Load 시 출력 메세지
        stdout.println("--------------------------------------------------------");
        stdout.println("Rudin Assistant Tool Version 23.11.");
        stdout.println("--------------------------------------------------------");
        stdout.println("Creators: Rudin");
        stdout.println("- Invalid Auth");
        stdout.println("- Info Exposure");
        stdout.println("- Reflected XSS");
        stdout.println("--------------------------------------------------------");
        stdout.println("Project Rudin Assist Tool");
        stdout.println("URL: https://github.com/rudin-kr/Burp_WallRuTools");
        stdout.println("--------------------------------------------------------");

        /*
         * 각 기능 별 Controller & JPanel 생성(View(UI)가 Controller 역할을 같이 함)
         * Java Swing 구조 때문에 Controller와 UI를 합침
         * 구시대 유물이라 그런지 Controller 개념 보다는
         * UI에서 Control 하는 개념인 듯
         */
        authCheckPanel = new AuthCheckMain(callbacks, helpers);    // 불충분한 인증 진단 Class 선언
        infoExposurePanel = new InfoExposureMain(callbacks, helpers);    // 정보 누출 진단 Class 선언
        reflectedXSSPanel = new ReflectedXSSMain(callbacks, helpers);    // 정보 누출 진단 Class 선언

        /*
         * 최초 실행인 경우 Config 반영
         */
        String configPath = callbacks.loadExtensionSetting("Rusist_Config_Path");
        if (configPath == null || configPath.isBlank()) {
            new ConfigUI(callbacks, configPath, this);
        }
        
        // 진단용 Class 의 UI는 여기서 추가
        /* class 추가할 때마다 아래 ExtensionMainUI에서 UI를 추가해줘야함
         * ViewController: 이 익스텐션의 메인/백그라운드/기본 UI
         */
        ExtensionMainUI extenderUI = new ExtensionMainUI(this);

        SwingUtilities.invokeLater(() -> {
            // add the custom tab to Burp's UI
            // 익스텐션의 UI(Controller)를 Burp에 연결
            callbacks.addSuiteTab(extenderUI);
        });
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        /*
         *  IHttpListener -> processHttpMessage Method Override
         *  This method is invoked when an HTTP request is about to be issued, and when an HTTP response has been received.
         *  HTTP Request가 발생하고, HTTP Response 데이터를 받은 경우 Callback?
         *
         *  활용: 새로운 기능을 하는 점검 도구를 추가해야하기 때문에 여기서는 파싱만 하고
         *       각 점검 Controller(Panel, UI)로 넘겨서 처리하는 게 맞을 듯
         *
         *  Parameter int toolFlag: Burp Suite의 어느 기능에서 왔니
         *  Parameter boolean messageIsRequest: HTTP Request Data - True, HTTP Response Data - False
         *  Parameter IHttpRequestResponse messageInfo: Data
         */

        // 일단 Proxy로 들어오는 HTTP에 대해서만 처리하자
        // 그리고, Burp -> Target -> Scope에 해당하는 패킷도...
        IRequestInfo request = helpers.analyzeRequest(messageInfo);
        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && callbacks.isInScope(request.getUrl())) {
            /* - 각 점검 Controller로 넘겨서 처리해야함
             * - Controller는 선언되어 있기 때문에, Data adding Method( addHTTP(messageIsRequest, messageInfo) )에서 처리해야할 듯
             *
             * ? 빠른 처리를 위해 Thread 쓸 까?
             * ? callbacks.registerHttpListener(this); 를 각 진단 class 안에서 등록할 까?
             */
            authCheckPanel.addHTTP(messageIsRequest, messageInfo); // 불충 인가 Main(취약점 진단 및 결과 저장)
            infoExposurePanel.addHTTP(messageIsRequest, messageInfo); // 정보 노출 Main(취약점 진단 및 결과 저장)
            reflectedXSSPanel.addHTTP(messageIsRequest, messageInfo); // Reflected XSS Main(취약점 진단 및 결과 저장)
        }
    }

    public boolean setConfig() {
        if(!authCheckPanel.updateConfig()) return false;
        if(!infoExposurePanel.updateConfig()) return false;
        return reflectedXSSPanel.updateConfig();
    }
}