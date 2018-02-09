package burp;

import org.json.JSONException;
import org.json.JSONObject;

import java.net.MalformedURLException;
import java.net.URL;

public class TraceItem
{
    boolean isRequest;
    byte[] message;
    URL url;

    TraceItem(IHttpRequestResponse messageInfo, boolean messageIsRequest)
    {
        isRequest = messageIsRequest;

        if(messageIsRequest)
        {
            try
            {
                IHttpService service = messageInfo.getHttpService();
                url = new URL(service.getProtocol(), service.getHost(), service.getPort(), "");
            }
            catch (MalformedURLException e)
            {
                // do nothing
            }
            message = messageInfo.getRequest();
        }
        else
        {
            message = messageInfo.getResponse();
        }
    }

    JSONObject marshall() throws JSONException
    {
        JSONObject rc = new JSONObject();
        rc.put("is_request", isRequest);
        rc.put("message", new String(message));
        if(isRequest)
        {
            rc.put("url", url.toString());
        }
        return rc;
    }
}
