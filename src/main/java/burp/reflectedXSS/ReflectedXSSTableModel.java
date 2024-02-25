package burp.reflectedXSS;

import javax.swing.table.AbstractTableModel;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ReflectedXSSTableModel extends AbstractTableModel {
    final String[] tableHeader = new String[]{"#", "Host", "Method", "Path", "Type(Header)", "Type(Body)", "Extension", "Count", "Size"};
    List<ReflectedXSSEntry> reflectedXssList = new ArrayList<>();

    public void addData(ReflectedXSSEntry data) {
        // 테이블 데이터 추가
        reflectedXssList.add(data);
//        fireTableDataChanged();
        fireTableRowsInserted(reflectedXssList.size()-1, reflectedXssList.size()-1);
    }

    @Override
    public int getRowCount() {
        return reflectedXssList.size();
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
        ReflectedXSSEntry reflectedXSSEntry = reflectedXssList.get(rowIndex);
        String file_path = reflectedXSSEntry.url.getFile();
        String file_ext = file_path.split("\\?")[0];
        file_ext = file_ext.contains(".")? file_ext.substring(file_ext.lastIndexOf(".")+1).toLowerCase():"";

        return new Object[]{
                reflectedXSSEntry.index,            // columnIndex = 0, #
                (reflectedXSSEntry.url.getProtocol() + "://" + reflectedXSSEntry.url.getHost()),  // columnIndex = 1, Host
                reflectedXSSEntry.method,           // columnIndex = 2, Method
                file_path,                          // columnIndex = 3, Path
                reflectedXSSEntry.respHeaderMame,   // columnIndex = 4, Response Header Mame Type
                reflectedXSSEntry.respBodyMame,     // columnIndex = 5, Response Body Mame Type
                file_ext,                           // columnIndex = 6, File Extension
                reflectedXSSEntry.howmany,          // columnIndex = 7, howmany(count)
                reflectedXSSEntry.respSize          // columnIndex = 8, Response Size
        }[columnIndex]; // switch case 대용
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // Integer 정렬이 제대로 되기 위함
        return (columnIndex == 0 || columnIndex == 7 || columnIndex == 8)? Integer.class:String.class;
    }

    public void removeRow(int row) {
        reflectedXssList.remove(row);
        fireTableRowsDeleted(row, row);
        fireTableDataChanged();
    }
}
