package burp;

import java.io.PrintStream;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


class MacroRunner implements Runnable
{
    MacrosMarshaller.Macro macro;
    ReplicatorPanel replicatorPanel;

    MacroRunner(MacrosMarshaller.Macro macro, ReplicatorPanel replicatorPanel)
    {
        this.macro = macro;
        this.replicatorPanel = replicatorPanel;
    }

    @Override
    public void run()
    {
        try
        {
            runMacro(macro, replicatorPanel);
        }
        catch(Exception ex)
        {
            ex.printStackTrace(new PrintStream(BurpExtender.callbacks.getStderr()));
        }
    }

    static void runMacro(MacrosMarshaller.Macro macro, ReplicatorPanel replicatorPanel) throws Exception
    {
        // TBD: this will trigger the session rule, then cause an unwanted request to /replicator-login
        IExtensionHelpers helpers = BurpExtender.callbacks.getHelpers();
        URL url = macro.getURL();
        IHttpService httpService = helpers.buildHttpService(url.getHost(), url.getPort(), url.getProtocol());
        List<String> headers = Arrays.asList("GET /replicator-login HTTP/1.0", "Host: " + url.getHost());
        byte[] request = helpers.buildHttpMessage(headers, new byte[0]);
        IHttpRequestResponse response = BurpExtender.callbacks.makeHttpRequest(httpService, request);
    }
}
