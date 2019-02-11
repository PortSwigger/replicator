package burp;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.List;
import java.util.regex.Pattern;


public class ReplicatorPanel extends JPanel implements HierarchyListener
{
    JTable issueTable;
    OptionsPanel optionsPanel;
    IMessageEditor requestEditor;
    IMessageEditor responseEditor;
    IssueTableModel issueTableModel;
    MessageEditorController messageEditorController = new MessageEditorController();
    File currentFile;
    boolean loggedIn = false;
    BurpExtender burpExtender;
    byte viewType;
    BufferedImage logo;
    JSplitPane topSplit;
    JSplitPane bottomSplit;
    String config = "{\n}";
    List<TraceItem> trace;

    ReplicatorPanel(BurpExtender burpExtender)
    {
        this.burpExtender = burpExtender;

        issueTableModel = new IssueTableModel();
        issueTable = new JTable(issueTableModel);
        issueTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        issueTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        issueTable.getColumnModel().getColumn(1).setPreferredWidth(250);
        issueTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        issueTable.getColumnModel().getColumn(3).setPreferredWidth(100);
        issueTable.getColumnModel().getColumn(4).setPreferredWidth(150);
        issueTable.getSelectionModel().addListSelectionListener(new ListSelectionListener(){
            public void valueChanged(ListSelectionEvent event)
            {
                Issue issue = issueTableModel.getIssue(issueTable.getSelectedRow());
                optionsPanel.setCurrentIssue(issue);
            }
        });

        optionsPanel = new OptionsPanel(this);
        JPanel panel = new JPanel();
        panel.setLayout(new BorderLayout());
        panel.add(new JScrollPane(optionsPanel), BorderLayout.WEST);
        topSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(issueTable), panel);
        topSplit.setResizeWeight(0.5);

        requestEditor = BurpExtender.callbacks.createMessageEditor(messageEditorController, false);
        responseEditor = BurpExtender.callbacks.createMessageEditor(messageEditorController, false);
        bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.getComponent(), responseEditor.getComponent());
        bottomSplit.setResizeWeight(0.5);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, topSplit, bottomSplit);

        this.setLayout(new BorderLayout());
        this.add(splitPane, BorderLayout.CENTER);

        BurpExtender.callbacks.customizeUiComponent(this);
        addHierarchyListener(this);
    }

    void acceptSendTo(IHttpRequestResponse[] requests)
    {
        for (IHttpRequestResponse request : requests)
        {
            if (request.getRequest() != null)
            {
                Issue issue = new Issue(request);
                issueTableModel.addIssue(issue);
                issueTable.setRowSelectionInterval(issue.row, issue.row);
                optionsPanel.addHost(issue.getHost()); // should be within addIssue?
            }
        }
        highlightTab();
    }

    void acceptSendTo(IScanIssue[] scanIssues)
    {
        for (IScanIssue scanIssue : scanIssues)
        {
            IHttpRequestResponse[] httpMessages = scanIssue.getHttpMessages();
            if(httpMessages.length > 0)
            {
                Issue issue = new Issue(httpMessages[0]);
                issue.issue = scanIssue.getIssueName();
                if(httpMessages[0] instanceof IHttpRequestResponseWithMarkers)
                {
                    IHttpRequestResponseWithMarkers message = (IHttpRequestResponseWithMarkers) httpMessages[0];
                    issue.parameter = getParameter(message);
                    List<int[]> markers = message.getRequestMarkers();
                    if(markers != null && !markers.isEmpty())
                    {
                        int[] marker = markers.get(0);
                        String payload = new String(message.getRequest()).substring(marker[0], marker[1]);
                        String collaboratorRegex = "\\w{30}\\." + BurpExtender.callbacks.createBurpCollaboratorClientContext().getCollaboratorServerLocation();
                        if(Pattern.compile(collaboratorRegex).matcher(payload).find())
                        {
                            issue.detectionMethod = Issue.DETECTION_COLLABORATOR;
                            issue.collaboratorReplace = collaboratorRegex;
                        }
                    }

                    markers = message.getResponseMarkers();
                    if(markers != null && !markers.isEmpty())
                    {
                        int[] marker = markers.get(0);
                        issue.grepExpression = BurpExtender.escapeRegex(new String(message.getResponse()).substring(marker[0], marker[1]));
                    }
                }
                issueTableModel.addIssue(issue);
                issueTable.setRowSelectionInterval(issue.row, issue.row);
                optionsPanel.addHost(issue.getHost());
            }
        }
        highlightTab();
    }

    String getParameter(IHttpRequestResponseWithMarkers message)
    {
        IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message.getRequest());
        List<int[]> markers = message.getRequestMarkers();
        if(markers != null && !markers.isEmpty())
        {
            int[] marker = markers.get(0);
            for(IParameter parameter : requestInfo.getParameters())
            {
                if(marker[0] >= parameter.getValueStart() && marker[1] <= parameter.getValueEnd())
                {
                    return parameter.getName();
                }
            }
        }
        return null;
    }

    void highlightTab()
    {
        if(tabbedPane != null)
        {
            for(int i = 0; i < tabbedPane.getTabCount(); i++)
            {
                if(tabbedPane.getComponentAt(i) == this)
                {
                    tabbedPane.setBackgroundAt(i, new Color(0xff6633));
                    Timer timer = new Timer(3000, new ActionListener()
                    {
                        @Override
                        public void actionPerformed(ActionEvent e)
                        {
                            for(int j = 0; j < tabbedPane.getTabCount(); j++)
                            {
                                if (tabbedPane.getComponentAt(j) == ReplicatorPanel.this)
                                {
                                    tabbedPane.setBackgroundAt(j, Color.BLACK);
                                    break;
                                }
                            }
                        }
                    });
                    timer.setRepeats(false);
                    timer.start();
                    break;
                }
            }
        }

    }

    JTabbedPane tabbedPane;
    ChangeListener changeListener;

    @Override
    public void hierarchyChanged(HierarchyEvent e)
    {
        tabbedPane = (JTabbedPane) getParent();
        changeListener = new ChangeListener() {
            public void stateChanged(ChangeEvent e) {
                if(tabbedPane.getSelectedComponent() == ReplicatorPanel.this)
                {
                    tabbedPane.setBackgroundAt(tabbedPane.getSelectedIndex(), Color.BLACK);
                    optionsPanel.loadMacros();
                }
            }
        };
        tabbedPane.addChangeListener(changeListener);
        removeHierarchyListener(this);
    }

    void removeChangeListener()
    {
        if (changeListener != null)
        {
            tabbedPane.removeChangeListener(changeListener);
        }
    }

    class MessageEditorController implements IMessageEditorController
    {
        @Override
        public IHttpService getHttpService() {
            return optionsPanel.currentIssue.getHttpService();
        }

        @Override
        public byte[] getRequest() {
            return optionsPanel.currentIssue.request;
        }

        @Override
        public byte[] getResponse() {
            return optionsPanel.currentIssue.response;
        }
    }

    void setViewType(byte viewType)
    {
        requestEditor = BurpExtender.callbacks.createMessageEditor(messageEditorController, viewType == BurpExtender.TESTER_VIEW);
        bottomSplit.setLeftComponent(requestEditor.getComponent());
        if(optionsPanel.currentIssue != null)
        {
            requestEditor.setMessage(optionsPanel.currentIssue.request == null ? OptionsPanel.EMPTY_MESSAGE : optionsPanel.currentIssue.request, true);
        }

        this.viewType = viewType;
        optionsPanel.setViewType(viewType);
        issueTableModel.setViewType(viewType);
    }
}
