package burp.infoexposure;

import burp.reflectedXSS.ReflectedXSSEntry;

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
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class InfoExposureTable extends JTable implements ActionListener{
    private final InfoExposureMain controller;
    // Right click menu elements
    private final JMenuItem menuItemIntruder;
    private final JMenuItem menuItemRepeater;
    private final JMenuItem menuItemCopyURL;
    private final JMenuItem menuItemDeleteItem;
    private final JMenuItem menuItemClearList;
    final TableRowSorter<InfoExposureTableModel> sorter;

    PrintWriter stdout;

    public InfoExposureTable(InfoExposureTableModel tableModel, InfoExposureMain controller) {
        super(tableModel);
        this.controller = controller;
        stdout = new PrintWriter(controller.callbacks.getStdout(), true);

        // Setting the colums width and center
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment( JLabel.CENTER );
        setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);

        getColumnModel().getColumn(0).setMaxWidth(30);
        getColumnModel().getColumn(0).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(1).setPreferredWidth(200);
        getColumnModel().getColumn(1).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(2).setMaxWidth(70);
        getColumnModel().getColumn(2).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(3).setPreferredWidth(500);
        getColumnModel().getColumn(4).setPreferredWidth(400);
        getColumnModel().getColumn(5).setMaxWidth(70);
        getColumnModel().getColumn(5).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(6).setMaxWidth(50);
        getColumnModel().getColumn(6).setCellRenderer( centerRenderer );
        getColumnModel().getColumn(7).setMaxWidth(50);
        getColumnModel().getColumn(7).setCellRenderer( centerRenderer );
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // Sorting
        sorter = new TableRowSorter<>(tableModel);
        setRowSorter(sorter);

        // Index 내림차순 기본 지정(최근 데이터가 위로 가도록)
        List<RowSorter.SortKey> sortKeys = new ArrayList<>();
        sortKeys.add(new RowSorter.SortKey(0, SortOrder.DESCENDING));
        sorter.setSortKeys(sortKeys);

        /* 마우스 우클릭 메뉴 */
        JPopupMenu popupMenu = new JPopupMenu();
        
        // 우클릭 메뉴의 아이템들 선언
        menuItemIntruder = new JMenuItem("Send request to Intruder");
        menuItemRepeater = new JMenuItem("Send request to Repeater");
        menuItemCopyURL = new JMenuItem("Copy URL");
        menuItemDeleteItem = new JMenuItem("Delete item");
        menuItemClearList = new JMenuItem("Clear list");
        
        // 우클릭 메뉴 아이템들 클릭 시 동작 mapping
        menuItemIntruder.addActionListener(this);
        menuItemRepeater.addActionListener(this);
        menuItemCopyURL.addActionListener(this);
        menuItemDeleteItem.addActionListener(this);
        menuItemClearList.addActionListener(this);

        // 우클릭 메뉴 -> 테이블 연결
        popupMenu.add(menuItemIntruder);
        popupMenu.add(menuItemRepeater);
        popupMenu.add(new JSeparator());
        popupMenu.add(menuItemCopyURL);
        popupMenu.add(menuItemDeleteItem);
        popupMenu.add(new JSeparator());
        popupMenu.add(menuItemClearList);

        setComponentPopupMenu(popupMenu);
        
        // 마우스 우 클릭 시 우 클릭한 행 자동 선택
        addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                Point point = e.getPoint();
                int currentRow = rowAtPoint(point);
                setRowSelectionInterval(currentRow, currentRow);
            }
        });
    }

    @Override
    public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
        // Table에서 선택한 Row 변경 시 호출되는 함수
        super.changeSelection(rowIndex, columnIndex, toggle, extend);
        
        rowIndex = convertRowIndexToModel(rowIndex);    // 저장된 Model에서 값이 저장된 행 재확인(Sort 이후 행이 바뀌기 떄문)
        InfoExposureEntry authCheckRow = controller.tableModel.infoExposureList.get(rowIndex);
        controller.requestViewer.setMessage(authCheckRow.httpRequestResponse.getRequest(), true);
        controller.responseViewer.setMessage(authCheckRow.httpRequestResponse.getResponse(),false);
        controller.currentlyDisplayedItem = authCheckRow.httpRequestResponse;
    }

    /* implements ActionListener
     * 마우스 우 클릭 시 Callback 함수
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        JMenuItem menu = (JMenuItem) e.getSource();
        // int row = this.getSelectedRow();  // Filter 된 Table에서 몇 번째 행인지 반환 -> 전체 원본 리스트와 일치하지 않기 때문에 문제 발생
        int index = (int) getValueAt(this.getSelectedRow(),0); // Column 0 = List index + 1
        List<InfoExposureEntry> historyList = controller.tableModel.infoExposureList;
        int row = -1;
        for(int i=0;i< historyList.size();i++){
            if(historyList.get(i).index == index) {
                row = i;
                break;
            }
        }

        // If no row is selected
        if (row == -1)  // 이런 경우는 없을 거 같지만 일단...시큐어코딩은 중요하니깐...
            return;
        InfoExposureEntry authCheckRow = controller.tableModel.infoExposureList.get(row);
        boolean useHttps = authCheckRow.url.getProtocol().equalsIgnoreCase("https");
        
        // 선택지가 적은 경우 switch 보다 if-else가 빠름
        // 선택지가 많아지는 경우 switch가 빠르다기 보단 일정한 성능을 보임
        if (menu == menuItemIntruder)
        {
            // Send the request to the Intruder
            controller.callbacks.sendToIntruder(authCheckRow.url.getHost(), authCheckRow.url.getPort(), useHttps,
                    authCheckRow.httpRequestResponse.getRequest(), authCheckRow.httpRequestResponse.getRequestMarkers());
        }
        else if (menu == menuItemRepeater)
        {
            // Send the request to the Repeater
            controller.callbacks.sendToRepeater(authCheckRow.url.getHost(), authCheckRow.url.getPort(), useHttps, authCheckRow.httpRequestResponse.getRequest(),null);
        }
        else if (menu == menuItemCopyURL)
        {
            // Copy URL to the clipboard
            StringSelection stringSelection = new StringSelection (authCheckRow.url.toString());
            Clipboard clpbrd = Toolkit.getDefaultToolkit ().getSystemClipboard ();
            clpbrd.setContents (stringSelection, null);
        }
        else if (menu == menuItemDeleteItem)
        {
            controller.tableModel.removeRow(row);

            // Clear request/response
            controller.requestViewer.setMessage(new byte[0], true);
            controller.responseViewer.setMessage(new byte[0], false);
        }
        else if (menu == menuItemClearList)
        {
            controller.tableModel.infoExposureList.clear();

            // Clear request/response
            controller.requestViewer.setMessage(new byte[0], true);
            controller.responseViewer.setMessage(new byte[0], false);

            //Reload the request table
            controller.tableModel.fireTableDataChanged();
        }
    }
}
