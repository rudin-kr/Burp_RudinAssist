package burp;

import burp.utils.ConfigUI;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class ExtensionMainUI implements ITab, IExtensionStateListener, IContextMenuFactory {
    private final IBurpExtenderCallbacks callbacks;
    private final JTabbedPane tabbedPane;
    private final PrintWriter stdout;
    private JPanel mainPanel;
    private JMenuBar burpMenuBar;
    private JMenu extensionMenu;

    public ExtensionMainUI(BurpExtender burpExtender) {
        callbacks = burpExtender.callbacks;
        stdout = new PrintWriter(callbacks.getStdout(), true);

        /* Tab 생성 및 연결 */
        tabbedPane = new JTabbedPane();
        tabbedPane.addTab("불충 인증", null, burpExtender.authCheckPanel, null);
        tabbedPane.addTab("정보 노출", null, burpExtender.infoExposurePanel, null);
        tabbedPane.addTab("Ref XSS", null, burpExtender.reflectedXSSPanel, null);

        createMainUI();
        createMenuUI(burpExtender);

        /*
         * Burp Suite Listener 등록
         * - registerExtensionStateListener: extensionUnloaded Method(Extension 미사용 시 실행) 구현
         */
        callbacks.registerExtensionStateListener(this);
        callbacks.registerContextMenuFactory(this);
    }

    private void createMenuUI(BurpExtender burpExtender) {
        try {
            burpMenuBar = Objects.requireNonNull(getBurpFrame()).getJMenuBar();
        } catch (Exception ignored) { }

        extensionMenu = new JMenu("Rudin Assist");

        /*
         * Create Menu Items
         */
        // Extension Config File Update
        JMenuItem configUpdateMI = new JMenuItem("Update Config File Path");
        configUpdateMI.addActionListener(e -> {
            String configPath = callbacks.loadExtensionSetting("Rusist_Config_Path");
            new ConfigUI(callbacks, configPath, burpExtender);
        });
        extensionMenu.add(configUpdateMI);
        burpMenuBar.add(extensionMenu);
    }

    private void createMainUI() {
        /* Burp Suite > mainPanel > componentWrapper > tabbedPane(각 기능 Pane) */
        mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        JPanel componentWrapper = new JPanel(new BorderLayout());
        componentWrapper.add(tabbedPane, BorderLayout.CENTER);
        mainPanel.add(componentWrapper, BorderLayout.CENTER);
    }

    private static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }

    @Override
    public String getTabCaption() {
        /* 탭에 표시할 이름 */
        return "Rudin Assist";
    }

    @Override
    public Component getUiComponent() {
        /* 전체 UI 반환 -> addSuiteTab() 에서 버프에 연결됨 */
        return mainPanel;
    }

    @Override
    public void extensionUnloaded() {
        burpMenuBar.remove(extensionMenu);
        burpMenuBar.revalidate();
        burpMenuBar.repaint();
        callbacks.saveExtensionSetting("Rusist_Config_Path", "");
        stdout.println("Rudin Assist Unloaded");
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        stdout.println("- ExtensionMenuUI > createMenuItems -");
        List<JMenuItem> list = new ArrayList<>();
        list.add(extensionMenu);
        return list;
    }
}
