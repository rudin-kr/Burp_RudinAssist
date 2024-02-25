package burp.infoexposure;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class InfoExposureTableModel extends AbstractTableModel {
    final String[] tableHeader = new String[]{"#", "Host", "Method", "Path", "Searched", "Extension", "Count", "Size"};
//    final Class<?>[] column_types = { Integer.class, String.class, String.class, String.class, String.class, String.class };
    List<InfoExposureEntry> infoExposureList = new ArrayList<>();

    public void addData(InfoExposureEntry data) {
        // 테이블 데이터 추가
        this.infoExposureList.add(data);
        // fireTableDataChanged();
        fireTableRowsInserted(infoExposureList.size()-1, infoExposureList.size()-1);
    }

    @Override
    public int getRowCount() {
        return infoExposureList.size();
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
        InfoExposureEntry infoExposureEntry = infoExposureList.get(rowIndex);
        String file_path = infoExposureEntry.url.getFile();
        String file_ext = file_path.split("\\?")[0];
        file_ext = file_ext.contains(".")? file_ext.substring(file_ext.lastIndexOf(".")+1).toLowerCase():"";
        return new Object[]{
                infoExposureEntry.index,                     // columnIndex = 0, #
                (infoExposureEntry.url.getProtocol() + "://" + infoExposureEntry.url.getHost()),  // columnIndex = 1, Host
                infoExposureEntry.method,          // columnIndex = 2, Method
                file_path,                         // columnIndex = 3, Path
                infoExposureEntry.search_result.toString(),   // columnIndex = 4, Searched Text
                file_ext,                          // columnIndex = 5, File Extension
                infoExposureEntry.count,            // columnIndex = 6, Seached Count
                infoExposureEntry.respSize          // columnIndex = 7, Response Size
        }[columnIndex]; // switch case 대용
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // Integer 정렬이 제대로 되기 위함
        return (columnIndex == 0 || columnIndex == 6 || columnIndex == 7)? Integer.class:String.class;
    }

    public void removeRow(int row) {
        infoExposureList.remove(row);
        fireTableRowsDeleted(row, row);
        fireTableDataChanged();
    }
}
