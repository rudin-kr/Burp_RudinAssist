package burp.reflectedXSS;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public class ReflectedXSSParameterTableModel extends AbstractTableModel {
    List<String[]> dataList = new ArrayList<>();
    final String[] tableHeader = new String[]{"#", "Parameter", "Result"};

    @Override
    public int getRowCount() {
        return dataList.size();
    }

    @Override
    public String getColumnName(int column) {
        return tableHeader[column];
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == 0? Integer.class:String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return (columnIndex == 0)? rowIndex + 1 : dataList.get(rowIndex)[columnIndex - 1];
    }
    public void setData(List<String[]> doubted_params) {
        dataList = doubted_params;
        fireTableDataChanged();
    }
}
