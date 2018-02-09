package burp;

import javax.swing.*;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;


public class Issue
{
    static final String IDENTITY_HEADER = "Replicator-identity: ";

    String id;
    String issue;
    String path;
    String parameter;
    byte status = STATUS_NOT_TESTED;
    boolean everVulnerable = false;
    String notes;
    List<String> sessionHandlingRules = new ArrayList<>();
    String uniqueId;
    byte detectionMethod = DETECTION_GREP;
    String grepExpression;
    String collaboratorReplace;
    int collaboratorTimeout = DEFAULT_COLLABORATOR_TIMEOUT;

    final static int DEFAULT_COLLABORATOR_TIMEOUT = 10;

    final static byte STATUS_NOT_TESTED = 0;
    final static byte STATUS_WORKING = 1;
    final static byte STATUS_ERROR = 2;
    final static byte STATUS_VULN = 3;
    final static byte STATUS_FIXED = 4;

    final static byte TEST_DETECTED = 0;
    final static byte TEST_NOT_DETECTED = 1;
    final static byte TEST_ERROR = 2;

    final static byte DETECTION_GREP = 1;
    final static byte DETECTION_COLLABORATOR = 2;

    URL url;
    byte[] request;
    byte[] response;

    IssueTableModel issueTableModel;
    int row;

    Issue()
    {
    }

    public Issue(IHttpRequestResponse request)
    {
        this.request = request.getRequest();
        this.response = request.getResponse();
        try
        {
            IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(request.getHttpService(), request.getRequest());

            SessionRulesMarshaller sessionHandlingRules = new SessionRulesMarshaller();
            this.sessionHandlingRules = sessionHandlingRules.getRulesForRequest(requestInfo);
            url = requestInfo.getUrl();
            path = url.getPath();
        }
        catch(Exception ex)
        {
            ex.printStackTrace(new PrintStream(BurpExtender.callbacks.getStderr()));
        }
    }

    public void startTest()
    {
        status = STATUS_WORKING;
        fireUpdate();
    }

    public void finishTest(byte testStatus)
    {
        if(testStatus == TEST_DETECTED)
        {
            status = STATUS_VULN;
            everVulnerable = true;
        }
        else if(testStatus == TEST_ERROR)
        {
            status = STATUS_ERROR;
        }
        else
        {
            if(everVulnerable)
            {
                status  = STATUS_FIXED;
            }
            else
            {
                status = STATUS_ERROR;
            }
        }
        fireUpdate();
    }

    public void fireUpdate()
    {
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                issueTableModel.fireTableCellUpdated(row, 4);
            }
        });
    }

    public String getStatus()
    {
        switch(status)
        {
            case STATUS_NOT_TESTED:
                return "";
            case STATUS_WORKING:
                return "Working...";
            case STATUS_ERROR:
                return "Unable to replicate";
            case STATUS_VULN:
                return "Vulnerable";
            case STATUS_FIXED:
                return "Resolved (tentative)";
            default:
                return "";
        }
    }

    String getSessionRules()
    {
        StringBuilder rc = new StringBuilder();
        for(String rule : sessionHandlingRules)
        {
            if(!rule.equals(("Use cookies from Burp's cookie jar")))
            {
                rc.append(rule).append(", ");
            }
        }
        return rc.length() < 2 ? "" : rc.substring(0, rc.length() - 2);
    }

    IHttpService getHttpService()
    {
        return BurpExtender.callbacks.getHelpers().buildHttpService(url.getHost(), url.getPort(), url.getProtocol());
    }

    String getHost()
    {
        String host = url.getHost();
        // TBD: don't include 80/443 ?
        host = host + String.format(":%d", url.getPort());
        return host;
    }

    void getCookieNames(Set<String> cookiesNames)
    {
        IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(request);
        for(IParameter parameter : requestInfo.getParameters())
        {
            if(parameter.getType() == IParameter.PARAM_COOKIE)
            {
                cookiesNames.add(parameter.getName());
            }
        }
    }

    void scrubCookies(Collection<String> cookieNames)
    {
        IExtensionHelpers helpers = BurpExtender.callbacks.getHelpers();
        for (String cookieName : cookieNames)
        {
            IParameter cookie = helpers.buildParameter(cookieName, "", IParameter.PARAM_COOKIE);
            request = helpers.removeParameter(request, cookie);
        }

        // If Cookie: header is empty, remove
        IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(request);
        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        List<String> headers = requestInfo.getHeaders();
        for (int i = 0; i < headers.size(); i++)
        {
            if (headers.get(i).equals("Cookie: "))
            {
                headers.remove(i);
                request = BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, body);
            }
        }
    }

    void setHost(String host, int port)
    {
        try
        {
            url = new URL(url.getProtocol(), host, port, url.getPath());
        } catch (MalformedURLException ex)
        {
            ex.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStderr()));
        }
        request = Utils.changeHost(request, host, port);
        clearStatus();
    }

    void clearStatus()
    {
        everVulnerable = false;
        status = STATUS_NOT_TESTED;
        fireUpdate();
    }

    byte[] getRequestWithIdentity()
    {
        uniqueId = Long.toHexString(new Random().nextLong());
        IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        headers.add(IDENTITY_HEADER + uniqueId);
        return BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, body);
    }
}
