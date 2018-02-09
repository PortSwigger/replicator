package burp;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MacrosMarshaller
{
    JSONObject root;
    JSONArray macros;

    MacrosMarshaller()
    {
        try
        {
            String json = BurpExtender.callbacks.saveConfigAsJson("project_options.sessions.macros");
            root = new JSONObject(new JSONTokener(json));
            macros = root.getJSONObject("project_options")
                    .getJSONObject("sessions")
                    .getJSONObject("macros")
                    .getJSONArray("macros");
        }
        catch(JSONException ex)
        {
            ex.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStderr()));
        }
    }

    List<String> getMacroNames() throws JSONException
    {
        List<String> rc = new ArrayList<>();
        for(int i = 0; i < macros.length(); i++)
        {
            rc.add(macros.getJSONObject(i).getString("description"));
        }
        return rc;
    }

    Macro getMacroByName(String name) throws JSONException
    {
        for(int i = 0; i < macros.length(); i++)
        {
            if(macros.getJSONObject(i).getString("description").equals(name))
            {
                return new Macro(macros.getJSONObject(i));
            }
        }
        return null;
    }

    Macro getMacroBySerial(Long serial) throws JSONException
    {
        for(int i = 0; i < macros.length(); i++)
        {
            if(macros.getJSONObject(i).getLong("serial_number") == serial)
            {
                return new Macro(macros.getJSONObject(i));
            }
        }
        return null;
    }

    void setProjectMacros(JSONArray newMacros) throws JSONException
    {
        Map<Long, JSONObject> macroMap = new HashMap<>();

        for(int i = 0; i < macros.length(); i++)
        {
            JSONObject macro = macros.getJSONObject(i);
            macroMap.put(macro.getLong("serial_number"), macro);
        }
        for(int i = 0; i < newMacros.length(); i++)
        {
            JSONObject macro = newMacros.getJSONObject(i);
            macroMap.put(macro.getLong("serial_number"), macro);
        }

        while(macros.length() > 0)
        {
            macros.remove(0);
        }
        for(JSONObject macro : macroMap.values())
        {
            macros.put(macro);
        }

        String json = root.toString(4);
        BurpExtender.callbacks.loadConfigFromJson(json);
    }

    class Macro
    {
        JSONObject json;

        Macro(JSONObject json)
        {
            this.json = json;
        }

        @Override
        public String toString()
        {
            try
            {
                return json.getString("description");
            }
            catch(Exception ex)
            {
                ex.printStackTrace(new PrintStream(BurpExtender.callbacks.getStderr()));
                return "";
            }
        }

        Long getSerial() throws JSONException
        {
            return json.getLong("serial_number");
        }

        URL getURL() throws JSONException, MalformedURLException
        {
            String url = json.getJSONArray("items").getJSONObject(0).getString("url");
            return new URL(url);
        }

        void changeTarget(String oldHost, int oldPort, String newHost, int newPort)
        {
            try
            {
                JSONArray items = json.getJSONArray("items");
                for(int i = 0; i < items.length(); i++)
                {
                    JSONObject item = items.getJSONObject(i);
                    if(item.getString("url").contains(String.format("://%s:%d", oldHost, oldPort)))
                    {
                        URL url = new URL(item.getString("url"));
                        URL newUrl = new URL(url.getProtocol(), newHost, newPort, url.getFile());
                        item.put("url", newUrl.toString());

                        byte[] request = item.getString("request").getBytes();
                        request = Utils.changeHost(request, newHost, newPort);
                        item.put("request", new String(request));
                    }
                }
            }
            catch (JSONException | MalformedURLException e)
            {
                e.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStderr()));
            }
        }
    }

}
