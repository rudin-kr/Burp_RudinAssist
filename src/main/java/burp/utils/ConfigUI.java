package burp.utils;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

public class ConfigUI extends JFrame {
    private final IBurpExtenderCallbacks callbacks;
    private final BurpExtender burpExtender;

    private JPanel configPanel;
    private JTextField configFileTextField;
    private final String configPath;

    private String open_create;
    private File configFile = null;
    private final PrintWriter stdout;

    public ConfigUI(IBurpExtenderCallbacks callbacks, String configPath) {

        this.callbacks = callbacks;
        this.configPath = configPath;
        this.burpExtender = null;

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("- 새로운 창에서 Config File의 경로를 지정해주세요.");

        createConfigUI();

        setJFrame();
    }

    public ConfigUI(IBurpExtenderCallbacks callbacks, String configPath, BurpExtender burpExtender) {

        this.callbacks = callbacks;
        this.configPath = configPath;
        this.burpExtender = burpExtender;

        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("- 새로운 창에서 Config File의 경로를 지정해주세요.");

        createConfigUI();

        setJFrame();
    }
    private void setJFrame() {
        /* JFrame 설정 */
        setTitle("Open/Create Config File(.json)");
        // setSize(600,120);
        
        // ConfigUI(JFrame) 크기 및 위치 설정
        // Get the current mouse pointer location
        Point mouseLocation = MouseInfo.getPointerInfo().getLocation();

        // Find the graphics device (monitor) containing the mouse pointer
        GraphicsDevice[] screenDevices = GraphicsEnvironment.getLocalGraphicsEnvironment().getScreenDevices();
        GraphicsDevice currentDevice = null;

        for (GraphicsDevice device : screenDevices) {
            Rectangle bounds = device.getDefaultConfiguration().getBounds();
            if (bounds.contains(mouseLocation)) {
                currentDevice = device;
                break;
            }
        }

        // If the current device is found, center the frame on that monitor
        if (currentDevice != null) {
            GraphicsConfiguration config = currentDevice.getDefaultConfiguration();
            Rectangle bounds = config.getBounds();

            int centerX = bounds.x + bounds.width / 2 - 300; // getWidth() / 2;
            int centerY = bounds.y + bounds.height / 2 - 60; //getHeight() / 2;

            //setLocation(centerX, centerY);
            setBounds(centerX, centerY, 600, 120);    // 마우스 포인터 위치에 창 Open
        } else {
            // Fallback to the default location if the device is not found
             setBounds(mouseLocation.x-100, mouseLocation.y, 600, 120);    // 마우스 포인터 위치에 창 Open
            setLocationRelativeTo(null);    // 메인 모니터 중앙에 생성
        }
        // Point mouse_location = MouseInfo.getPointerInfo().getLocation();
        // setBounds(mouse_location.x-100, mouse_location.y, 600, 120);    // 마우스 포인터 위치에 창 Open
        // JFrame을 가운데 정렬 - 이게 있으면 메인 모니터에만 생성됨
        // setLocationRelativeTo(null);

        // JFrame 표시
        setVisible(true);
    }

    private void createConfigUI() {
        configPanel = new JPanel();
        configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));

        /* 설정 파일 위치 Layout */
        Box configPathBox = Box.createHorizontalBox();
        configPathBox.add(Box.createHorizontalStrut(5));  // spacing between button
        configPathBox.add(new JLabel("[Apply 버튼으로 적용] Path"));
        configFileTextField = new JTextField(configPath,50);
        configFileTextField.setEditable(false);
        Border configPathLine = BorderFactory.createTitledBorder(" Config 파일 Path ");   // 테두리
        configPathBox.setBorder(configPathLine);
        configPathBox.add(Box.createHorizontalStrut(5));  // spacing between button
        configPathBox.add(configFileTextField);
        
        // 설정 파일 위치 Input 행 추가
        configPanel.add(configPathBox);

        /* 설정 Cancel, Apply 버튼 */
        set_config_buttons();

        // Apply 버튼 정의
        JButton apply_button = new JButton("Apply");
        apply_button.addActionListener(e -> {
            if(configFile == null){
                // Config File 없음
                JOptionPane.showMessageDialog(null, "Config File을 선택 또는 생성해주세요.", "선언되지 않은 Config File", JOptionPane.ERROR_MESSAGE);
            } else {
                if("create".equals(open_create)){
                    try {
                        // Files.write(configFile.toPath(), "{\"Empty\":\"Empty\"}".getBytes(), StandardOpenOption.CREATE);
                        Files.write(configFile.toPath(), "{}".getBytes(), StandardOpenOption.CREATE);
                    } catch (IOException except) {
                        stdout.println("설정파일 생성 중 오류 발생");
                    }
                }
                // Apply Click 시 Config Path -> 버프에 저장
                callbacks.saveExtensionSetting("Rusist_Config_Path", configFileTextField.getText());
                if(burpExtender == null){
                    // 각 진단 탭에서 설정 버튼을 클릭한 경우임
                    dispose();
                } else if(burpExtender.setConfig()) {
                    // Config가 정상적으로 적용되었을 때 종료
                    JOptionPane.showMessageDialog(null, "Config File이 설정 되었습니다.", "Config File 설정 완료", JOptionPane.INFORMATION_MESSAGE);
                    dispose();
                } else {
                    // Config 적용에 실패했을 경우
                    JOptionPane.showMessageDialog(null, "Config 적용 중 오류가 발생했습니다.\n올바른 Config File을 선택해주세요.", "잘못된 Config File", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        configPathBox.add(Box.createHorizontalStrut(10));  // spacing between button
        configPathBox.add(apply_button);

        // JPanel을 JFrame에 추가
        getContentPane().add(configPanel);
    }

    private void set_config_buttons() {
        /* 버튼 영역 설정 */
        JPanel buttonPanel = new JPanel();  // 버튼 전체 영역
        buttonPanel.setLayout(new BorderLayout());
        buttonPanel.setMaximumSize(new Dimension(10000, 30));   // Height 고정하려고 만듬, width는 상관없어서 크게 잡음
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5,1,0,1));
//        buttonPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));  // 영역 표시

        Box buttonBox = Box.createHorizontalBox();  // 버튼 그룹 영역

        buttonPanel.add(buttonBox, BorderLayout.EAST);  // 꼭 이렇게 해야 정렬됨 ㅡㅡ
        configPanel.add(buttonPanel);    // 버튼 영역 Config UI에 추가

        /* Open, Create, Apply, Cancel 버튼 정의 */
        // Open 버튼 정의
        JButton open_button = new JButton("Open");
        // 파일 선택 대화상자 생성
        open_button.addActionListener(e -> {
            configFile = chooseConfigFile("open");
            configFileTextField.setText((configFile == null)? "": configFile.getAbsolutePath());
        });
        buttonBox.add(open_button);

        // spacing between button
        buttonBox.add(Box.createHorizontalStrut(10));
        
        JButton create_button = new JButton("Create");
        create_button.addActionListener(e -> {
            configFile = chooseConfigFile("create");
            configFileTextField.setText((configFile == null)? "": configFile.getAbsolutePath());
        });
        buttonBox.add(create_button);

        // spacing between button
        buttonBox.add(Box.createHorizontalStrut(10));

        // Cancel 버튼 정의
        JButton cancel_button = new JButton("Cancel");
        cancel_button.addActionListener(e -> dispose());
        buttonBox.add(cancel_button);
    }

    private File chooseConfigFile(String openORcreate) {
        // 파일 탐색기? 실행 
        JFileChooser chooser;
        if(configPath == null || configPath.isBlank()){
            chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory()); // 디렉토리 설정(바탕화면...?)
        } else {
            chooser = new JFileChooser(configPath); // 디렉토리 설정
        }
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES); // 파일 선택 모드

        // JSON 파일 필터
        chooser.setAcceptAllFileFilterUsed(true);   // Filter 모든 파일 적용
        FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON file", "json");
        chooser.setFileFilter(filter);

        this.open_create = openORcreate;
        int userSelection;
        if("open".equals(openORcreate)) {
            // 설정 파일 열기
            chooser.setDialogTitle("열기: 설정파일(json)"); // 창의 제목
            userSelection = chooser.showOpenDialog(null); // 열기용 창 오픈
        } else {
            // 설정 파일 생성
            chooser.setDialogTitle("생성: 설정파일(json)"); // 창의 제목
            userSelection = chooser.showSaveDialog(null); // 생성용 창 오픈
        }
        
        if(userSelection == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile(); // 열기 또는 생성 클릭
            if(selected.isFile()) {
                String file_name = selected.getName();
                int file_ext_index = file_name.lastIndexOf(".");

                if(file_ext_index == -1 || file_ext_index == file_name.length() -1 ){
                    // 유효하지 않은 확장자 위치
                    JOptionPane.showMessageDialog(null, "선택된 파일이 유효하지 않습니다.\n올바른 Config File을 선택해주세요.", "잘못된 Config File 선택", JOptionPane.ERROR_MESSAGE);
                    return null;
                } else if("json".equalsIgnoreCase(file_name.substring(file_ext_index + 1))) {
                    // 확장자 json 확인
                    return selected;
                } else {
                    // 확장자 json 아님
                    JOptionPane.showMessageDialog(null, "파일의 확장자가 유효하지 않습니다.\n올바른 Config File을 선택해주세요.", "잘못된 Config File 선택", JOptionPane.ERROR_MESSAGE);
                    return null;
                }
            } else {
                // 디렉토리를 선택함 -> 다시하셈
                JOptionPane.showMessageDialog(null, "Config File이 아닌 폴더/디렉토리를 선택했습니다.\n올바른 Config File을 선택해주세요.", "잘못된 Config File 선택", JOptionPane.ERROR_MESSAGE);
                return null;
            }
        } else {
            return null;  // 취소
        }
    }
}
