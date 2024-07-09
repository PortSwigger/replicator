package burp;


import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import static java.awt.EventQueue.invokeLater;

public class BurpExtender implements IBurpExtender, IExtensionStateListener, ITab, IContextMenuFactory, IHttpListener
{
    static final String name = "Replicator";
    static final byte TESTER_VIEW = 1;
    static final byte DEVELOPER_VIEW = 0;

    ReplicatorPanel replicatorPanel;
    static IBurpExtenderCallbacks callbacks;
    JMenuBar burpMenuBar;
    burp.Menu replicatorMenu;
    byte viewType = DEVELOPER_VIEW;
    IssueChecker issueChecker;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        BurpExtender.callbacks = callbacks;
        replicatorPanel = new ReplicatorPanel(this);
        callbacks.setExtensionName(BurpExtender.name);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerExtensionStateListener(this);
        callbacks.addSuiteTab(this);
        callbacks.registerHttpListener(this);

        try
        {
            viewType = (byte) Integer.parseInt(callbacks.loadExtensionSetting("viewType"));
        }
        catch(Exception ex)
        {
            // ignore
        }

        replicatorPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                if (replicatorPanel.getWidth() > 0)
                {
                    replicatorPanel.removeComponentListener(this);

                    invokeLater(() -> {
                        replicatorMenu = new Menu(BurpExtender.this);
                        replicatorMenu.setViewType(viewType);

                        burpMenuBar = getBurpFrame().getJMenuBar();
                        burpMenuBar.add(replicatorMenu);
                        burpMenuBar.validate();

                        setViewType(viewType);
                    });
                }
            }
        });
    }

    @Override
    public void extensionUnloaded() {
        if(issueChecker != null)
        {
            issueChecker.terminating = true;
        }

        replicatorPanel.removeChangeListener();

        invokeLater(() -> {
            burpMenuBar.remove(replicatorMenu);
            burpMenuBar.repaint();
        });
    }

    @Override
    public String getTabCaption() {
        return BurpExtender.name;
    }

    @Override
    public Component getUiComponent() {
        return replicatorPanel;
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
    {
        if(viewType == DEVELOPER_VIEW)
        {
            return null;
        }
        else
        {
            JMenuItem menuItem = new JMenuItem("Send to Replicator");
            menuItem.addActionListener(new ContextMenuListener(invocation));
            return Arrays.asList(menuItem);
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if(replicatorPanel.trace != null)
        {
            replicatorPanel.trace.add(new TraceItem(messageInfo, messageIsRequest));
        }

        if (!messageIsRequest)
        {
            return;
        }

        byte[] request = messageInfo.getRequest();
        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(request);
        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        List<String> headers = requestInfo.getHeaders();
        for (int i = 0; i < headers.size(); i++)
        {
            if (headers.get(i).startsWith(Issue.IDENTITY_HEADER))
            {
                String uniqueId = headers.get(i).substring(Issue.IDENTITY_HEADER.length());
                headers.remove(i);
                request = BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, body);
                messageInfo.setRequest(request);
                for(Issue issue : replicatorPanel.issueTableModel.issues)
                {
                    if(uniqueId.equals(issue.uniqueId))
                    {
                        issue.request = request;
                        if(replicatorPanel.optionsPanel.currentIssue == issue)
                        {
                            replicatorPanel.requestEditor.setMessage(request, true);
                        }
                    }
                }
                break;
            }
        }
    }

    class ContextMenuListener implements ActionListener
    {
        IContextMenuInvocation invocation;
        ContextMenuListener(IContextMenuInvocation invocation)
        {
            this.invocation = invocation;
        }

        @Override
        public void actionPerformed(ActionEvent e)
        {
            if(invocation.getSelectedMessages() != null)
            {
                replicatorPanel.acceptSendTo(invocation.getSelectedMessages());
            }
            if(invocation.getSelectedIssues() != null)
            {
                replicatorPanel.acceptSendTo(invocation.getSelectedIssues());
            }
        }
    }

    static JFrame getBurpFrame()
    {
        for(Frame f : Frame.getFrames())
        {
            if(f.isVisible() && f.getTitle().startsWith(("Burp Suite")))
            {
                return (JFrame) f;
            }
        }
        return null;
    }

    void setViewType(byte viewType)
    {
        this.viewType = viewType;
        replicatorPanel.setViewType(viewType);
    }

    static String escapeRegex(String regex)
    {
        Pattern regexMetaChars = Pattern.compile("[\\\\\\[\\](){}.\\^$?*+|]");
        return regexMetaChars.matcher(regex).find() ? Pattern.quote(regex) : regex;
    }
}
