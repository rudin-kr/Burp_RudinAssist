package burp.authcheck;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class AuthCheckConfigTableModel  extends AbstractTableModel {
    String[] columns = {"Enabled", "Host", "Header", "Target", "Edit", "Delete"};
    String[] hashmap_keys = {"onoff", "host", "header", "target", "edit"};
    List<HashMap<String, Object>> testConfList = new ArrayList<>();

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // CheckBox
        return columnIndex == 0? Boolean.class:String.class;
    }

    @Override
    public String getColumnName(int column) {
        return columns[column];
    }

    @Override
    public int getRowCount() {
        return testConfList.size();
    }

    @Override
    public int getColumnCount() {
        return columns.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        HashMap<String, Object> test_conf = testConfList.get(rowIndex);
        return new Object[]{
                test_conf.get("onoff"),
                test_conf.get("host"),
                test_conf.get("header"),
                test_conf.get("target"),
                test_conf.get("edit"),
                null
        }[columnIndex];
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        /* JTable의 셀을 편집하고 엔터를 치면 호출되는 메소드 */
        HashMap<String, Object> test_conf = testConfList.get(rowIndex);
        test_conf.put(hashmap_keys[columnIndex], value);
        testConfList.set(rowIndex, test_conf);
        fireTableCellUpdated(rowIndex, columnIndex);//모든 리스너에게 셀 데이터 변경을 알린다
//        fireTableDataChanged();
    }

    public void setData(List<HashMap<String, Object>> dataList){
        testConfList = new ArrayList<>();
        // 2차원의 경우 반복문을 통해서 원소를 Deep Copy 해야 함...
        for(HashMap<String, Object> conf: dataList){
            testConfList.add(new HashMap<>() {{
                put("onoff", conf.get("onoff"));
                put("host", conf.get("host"));
                put("header", conf.get("header"));
                put("target", conf.get("target"));
                put("edit", conf.get("edit"));
            }});
        }
        fireTableDataChanged();
    }

    public void addData(HashMap<String, Object> data) {
        // 테이블 데이터 추가
        testConfList.add(data);
        fireTableDataChanged();
    }

    public void removeRow(int rowIndex){
        testConfList.remove(rowIndex);
        fireTableDataChanged();
    }

    public List<HashMap<String, Object>> getData(){
        return testConfList;
    }
}
