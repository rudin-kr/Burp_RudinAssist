package burp.utils;

import org.json.JSONObject;
import org.json.JSONTokener;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class Utils {
    public static String jFileChooserUtil(String configPath){
        JFileChooser chooser;
        if(configPath == null || configPath.isBlank()){
            chooser = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory()); // 디렉토리 설정(바탕화면...?)
        } else {
            chooser = new JFileChooser(configPath); // 디렉토리 설정
        }
        chooser.setDialogTitle("열기: 설정파일(json)"); // 창의 제목
        chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES); // 파일 선택 모드

        // JSON 파일 필터
        chooser.setAcceptAllFileFilterUsed(true);   // Filter 모든 파일 적용
        FileNameExtensionFilter filter = new FileNameExtensionFilter("JSON file", "json");
        chooser.setFileFilter(filter);

        int returnVal = chooser.showOpenDialog(null); // 열기용 창 오픈

        if(returnVal == JFileChooser.APPROVE_OPTION) { // 열기를 클릭
            return chooser.getSelectedFile().toString();
        } else {
            return configPath;
        }
    }

    public static void save_rule(JSONObject rule_json_object, String configPath, String conf_group_name) {
        try {

            JSONObject allConfig = new JSONObject(new JSONTokener(new FileReader(configPath)));
            allConfig.put(conf_group_name, rule_json_object);

            FileWriter file = new FileWriter(configPath);
            file.write(allConfig.toString());
            file.flush();
            file.close();
        } catch (IOException e) {
            // stdout.println("Rule 파일 작성 중 오류 발생");
            throw new RuntimeException(e);
        }
    }
}
