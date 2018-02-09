package burp;

import javax.swing.*;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import java.util.*;


public class IssueTableModel extends AbstractTableModel
{
    static List<String> columns = Arrays.asList("ID", "Issue", "Path", "Parameter", "Status");
    List<Issue> issues = new ArrayList<Issue>();
    boolean editable;
    int idCounter = 1;

    @Override
    public int getRowCount()
    {
        return issues.size();
    }

    @Override
    public int getColumnCount()
    {
        return columns.size();
    }

    @Override
    public String getColumnName(int column)
    {
        return columns.get(column);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        Issue issue = issues.get(rowIndex);
        switch(columnIndex)
        {
            case 0:
                return issue.id;
            case 1:
                return issue.issue;
            case 2:
                return issue.path;
            case 3:
                return issue.parameter;
            case 4:
                return issue.getStatus();
            default:
                return null;
        }
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex)
    {
        Issue issue = issues.get(rowIndex);
        switch(columnIndex)
        {
            case 0:
                issue.id = (String) value;
                break;
            case 1:
                issue.issue = (String) value;
                break;
            case 2:
                issue.path = (String) value;
                break;
            case 3:
                issue.parameter = (String) value;
                break;
        }

    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex)
    {
        return editable && columnIndex != 4;
    }

    public void addIssue(Issue issue)
    {
        if(issue.id == null)
        {
            issue.id = Integer.toString(idCounter);
            idCounter++;
        }
        issue.issueTableModel = this;
        issue.row = issues.size();
        issues.add(issue);
        fireTableRowsInserted(issue.row, issue.row);
    }

    public Issue getIssue(int index)
    {
        try
        {
            return issues.get(index);
        }
        catch(ArrayIndexOutOfBoundsException ex)
        {
            return null;
        }
    }

    public void deleteIssues(int[] indexes)
    {
        List<Integer> indexList = new ArrayList<>();
        for(int index : indexes)
        {
            indexList.add(index);
        }
        Collections.sort(indexList, Collections.reverseOrder());
        for(int index : indexList)
        {
            issues.remove(index);
            for (int j = index; j < issues.size(); j++)
            {
                issues.get(j).row -= 1;
            }
            fireTableRowsDeleted(index, index);
        }
    }

    void setViewType(byte viewType)
    {
        editable = (viewType == BurpExtender.TESTER_VIEW);
    }

    Set<String> getCookiesNames()
    {
        Set<String> cookiesNames = new HashSet<>();
        for(Issue issue : getSelectedIssues())
        {
            issue.getCookieNames(cookiesNames);
        }
        return cookiesNames;
    }

    void scrubCookies(Collection<String> cookieNames)
    {
        for(Issue issue : getSelectedIssues())
        {
            issue.scrubCookies(cookieNames);
        }
    }

    List<Issue> getSelectedIssues()
    {
        for (TableModelListener tml : getTableModelListeners())
        {
            if (tml instanceof JTable)
            {
                List<Issue> selectedIssues = new ArrayList<>();
                for (int row : ((JTable) tml).getSelectedRows())
                {
                    selectedIssues.add(issues.get(row));
                }
                return selectedIssues;
            }

        }
        return Collections.EMPTY_LIST;
    }
}
