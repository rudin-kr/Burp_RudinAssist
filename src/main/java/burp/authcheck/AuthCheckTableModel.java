package burp.authcheck;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class AuthCheckTableModel extends AbstractTableModel {
    final String[] tableHeader = new String[]{"#", "Host", "Method", "Path", "Session", "Extension", "Compare", "Size"};
//    final Class<?>[] column_types = { Integer.class, String.class, String.class, String.class, String.class, String.class };
    List<AuthCheckEntry> authCheckList = new ArrayList<>();

    public void addData(AuthCheckEntry data) {
        // 테이블 데이터 추가
        this.authCheckList.add(data);
        fireTableDataChanged();
    }

    @Override
    public int getRowCount() {
        return authCheckList.size();
    }

    @Override
    public String getColumnName(int column) {
        return tableHeader[column];
    }

    @Override
    public int getColumnCount() {
        return tableHeader.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        // 테이블에 각 row, column에 해당하는 값을 출력하는 방법 정의
        AuthCheckEntry authCheckEntry = authCheckList.get(rowIndex);
        String file_path = authCheckEntry.url.getFile();
        String file_ext = file_path.split("\\?")[0];
        file_ext = file_ext.contains(".")? file_ext.substring(file_ext.lastIndexOf(".")+1).toLowerCase():"";
        return new Object[]{
                authCheckEntry.index,                     // columnIndex = 0, #
                (authCheckEntry.url.getProtocol() + "://" + authCheckEntry.url.getHost()),  // columnIndex = 1, Host
                authCheckEntry.method,          // columnIndex = 2, Method
                file_path,                      // columnIndex = 3, Path
                authCheckEntry.session,         // columnIndex = 4, Session
                file_ext,                       // columnIndex = 5, File Extension
                authCheckEntry.compare_result,
                authCheckEntry.respSize          // columnIndex = 7, Response Size// columnIndex = 6, Compare
        }[columnIndex]; // switch case 대용
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // Integer 정렬이 제대로 되기 위함
        return (columnIndex == 0 || columnIndex == 7)? Integer.class:String.class;
    }

    public void removeRow(int row) {
        authCheckList.remove(row);
        fireTableRowsDeleted(row, row);
        fireTableDataChanged();
    }
}
