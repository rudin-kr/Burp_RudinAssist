package burp.reflectedXSS;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class ReflectedXSSParameterTable extends JTable implements ActionListener {
    private final ReflectedXSSMain controller;
    private final JMenuItem menuCopyParam;
    private final JMenuItem menuCopyCell;
    private final JMenuItem menuCopyRow;
    final TableRowSorter<ReflectedXSSParameterTableModel> sorter;

    public ReflectedXSSParameterTable(ReflectedXSSParameterTableModel paramTableModel, ReflectedXSSMain controller) {
        super(paramTableModel);
        this.controller = controller;

        // Setting the colums width and center
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment( JLabel.CENTER );
        setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

        getColumnModel().getColumn(0).setMaxWidth(30);
        getColumnModel().getColumn(0).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(1).setPreferredWidth(70);
//        getColumnModel().getColumn(1).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(2).setPreferredWidth(100);
//        getColumnModel().getColumn(2).setCellRenderer( centerRenderer );
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Sorting
        sorter = new TableRowSorter<>(paramTableModel);
        setRowSorter(sorter);

        /* 마우스 우클릭 메뉴 */
        JPopupMenu popupMenu = new JPopupMenu();
        menuCopyParam = new JMenuItem("Copy this Parameter Name, Value");
        menuCopyCell =  new JMenuItem("Copy this value at Mouse point");
        menuCopyRow =  new JMenuItem("Copy this row");

        // 우클릭 메뉴 아이템들 클릭 시 동작 mapping
        menuCopyParam.addActionListener(this);
        menuCopyCell.addActionListener(this);
        menuCopyRow.addActionListener(this);

        // 우클릭 메뉴 -> 테이블 연결
        popupMenu.add(menuCopyParam);
        popupMenu.add(menuCopyCell);
        popupMenu.add(menuCopyRow);

        setComponentPopupMenu(popupMenu);

        // 마우스 우 클릭 시 우 클릭한 행 자동 선택
        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                Point point = e.getPoint();
                int row = rowAtPoint(point);
                int column = columnAtPoint(point);
                setColumnSelectionInterval(column, column); // Auto Column 선택
                setRowSelectionInterval(row, row);  // Auto Row 선택
            }
        });
    }

    @Override   // Cell 값 복사하라고...
    public boolean isCellEditable(int row, int column) {
        return column != 0;
    }

    /* implements ActionListener
     * 마우스 우 클릭 시 Callback 함수
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        JMenuItem menu = (JMenuItem) e.getSource();
        int row = this.getSelectedRow();
        int cell = this.getSelectedColumn();

        // If no row is selected
        if (row == -1)  // 이런 경우는 없을 거 같지만 일단...시큐어코딩은 중요하니깐...
            return;
        String[] paramRow = controller.paramTableModel.dataList.get(row);

        if (menu == menuCopyParam)
        {
            // Copy Row to the clipboard
            StringSelection stringSelection = new StringSelection (paramRow[0]);
            Clipboard clpbrd = Toolkit.getDefaultToolkit ().getSystemClipboard ();
            clpbrd.setContents (stringSelection, null);
        }
        else if (menu == menuCopyCell)
        {
            // Send the request to the Repeater
            StringSelection stringSelection = new StringSelection (paramRow[cell-1]);
            Clipboard clpbrd = Toolkit.getDefaultToolkit ().getSystemClipboard ();
            clpbrd.setContents (stringSelection, null);
        }
        else if (menu == menuCopyRow)
        {
            // Send the request to the Repeater
            StringSelection stringSelection = new StringSelection (paramRow[0] + "|" + paramRow[1]);
            Clipboard clpbrd = Toolkit.getDefaultToolkit ().getSystemClipboard ();
            clpbrd.setContents (stringSelection, null);
        }
    }
}
