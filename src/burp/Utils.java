package burp;

import java.util.Arrays;
import java.util.List;

public class Utils
{

    static byte[] changeHost(byte[] request, String host, int port)
    {
        IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(request);
        List<String> headers = requestInfo.getHeaders();
        byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
        for (int i = 0; i < headers.size(); i++)
        {
            if (headers.get(i).startsWith("Host:"))
            {
                headers.set(i, String.format("Host: %s:%d", host, port));
                break;
            }
        }
        return BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, body);
    }
}
