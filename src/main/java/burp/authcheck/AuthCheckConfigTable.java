package burp.authcheck;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;

public class AuthCheckConfigTable extends JTable {
    private final AuthCheckConfigTableModel tableModel;

    public AuthCheckConfigTable(TableModel tableModel) {
        super(tableModel);
        this.tableModel = (AuthCheckConfigTableModel) tableModel;

        // 각 행 onoff -> 체크 박스로 변환
        JCheckBox enableCheckBox = new JCheckBox();
        getColumn("Enabled").setCellRenderer(new Enable_CheckBox_Cell(enableCheckBox));
        getColumn("Enabled").setCellEditor(new DefaultCellEditor(enableCheckBox));

        // 각 행마다 삭제 버튼 추가
        getColumn("Delete").setCellRenderer(new Edit_Remove_Button_Cell());
        getColumn("Delete").setCellEditor(new Edit_Remove_Button_Cell());

        // Column 넓이
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment( JLabel.CENTER );
        getColumnModel().getColumn(0).setMaxWidth(70);
        getColumnModel().getColumn(1).setPreferredWidth(150);
        getColumnModel().getColumn(1).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(2).setMaxWidth(70);
        getColumnModel().getColumn(2).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(3).setPreferredWidth(200);
        getColumnModel().getColumn(4).setPreferredWidth(100);
        getColumnModel().getColumn(5).setMaxWidth(70);
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        // 모든 데이터 수정 가능
        return true;
    }
    static class Enable_CheckBox_Cell extends DefaultTableCellRenderer {
        private final JCheckBox enableCheckBox;

        public Enable_CheckBox_Cell(JCheckBox enableCheckBox) {
            this.enableCheckBox = enableCheckBox;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            enableCheckBox.setSelected(((boolean) value));
            enableCheckBox.setHorizontalAlignment(JLabel.CENTER);
            return enableCheckBox;
        }
    }

    class Edit_Remove_Button_Cell extends AbstractCellEditor implements TableCellEditor, TableCellRenderer {

        JButton rowControllButton;

        public Edit_Remove_Button_Cell() {
            rowControllButton = new JButton("삭제");
            rowControllButton.addActionListener(e -> removeSelectedRow());
        }

        private void removeSelectedRow(){
            int row = getSelectedRow();
            // 삭제 버튼 클릭 시 셀이 수정모드로 바뀌기 때문에 ESC를 꼭 눌러야 하는 버그가 있음
            // row 초기화 이후 강제로 수정상태를 취소 시키는 코드임
            if (cellEditor != null) {
                if (cellEditor.getCellEditorValue() != null) {
                    cellEditor.stopCellEditing();
                } else {
                    cellEditor.cancelCellEditing();
                }
            }
            tableModel.removeRow(row);
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            return rowControllButton;
        }

        @Override
        public Object getCellEditorValue() {
            return null;
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            return rowControllButton;
        }
    }
}
