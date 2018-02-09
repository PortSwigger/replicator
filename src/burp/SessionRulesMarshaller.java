package burp;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.InputStream;
import java.io.PrintStream;
import java.net.URL;
import java.util.*;
import java.util.regex.Pattern;

public class SessionRulesMarshaller
{
    List<Rule> rules = new ArrayList<>();
    JSONObject root;
    JSONArray sessionHandlingRules;
    JSONObject targetScope;

    void setProjectSessionRule(JSONObject newSessionRule) throws JSONException
    {
        JSONArray newSessionRules = new JSONArray();
        newSessionRules.put(newSessionRule);
        newSessionRules.put(genereateUseCookiesSessionRule());
        setProjectSessionRules(newSessionRules);
    }

    void setProjectSessionRules(JSONArray newSessionRules) throws JSONException
    {
        Map<String, JSONObject> ruleMap = new HashMap<>();

        for(int i = 0; i < sessionHandlingRules.length(); i++)
        {
            JSONObject rule = sessionHandlingRules.getJSONObject(i);
            ruleMap.put(rule.getString("description"), rule);
        }
        for(int i = 0; i < newSessionRules.length(); i++)
        {
            JSONObject rule = newSessionRules.getJSONObject(i);
            ruleMap.put(rule.getString("description"), rule);
        }

        while(sessionHandlingRules.length() > 0)
        {
            sessionHandlingRules.remove(0);
        }
        for(JSONObject rule : ruleMap.values())
        {
            sessionHandlingRules.put(rule);
        }

        String json = root.toString(4);
        BurpExtender.callbacks.loadConfigFromJson(json);
    }

    static JSONObject genereateLoginSessionRule(Long serial, URL url) throws JSONException
    {
        InputStream inputStream = SessionRulesMarshaller.class.getResourceAsStream("LoginSessionRule.json");
        Scanner s = new Scanner(inputStream).useDelimiter("\\A");
        String ruleString = s.hasNext() ? s.next() : "";
        JSONObject sessionrule = new JSONObject(new JSONTokener(ruleString));
        sessionrule.getJSONArray("actions").getJSONObject(0).put("macro_serial_number", serial);
        sessionrule.getJSONArray("include_in_scope").getJSONObject(0).put("host", url.getHost());
        return sessionrule;
    }

    static JSONObject genereateUseCookiesSessionRule() throws JSONException
    {
        InputStream inputStream = SessionRulesMarshaller.class.getResourceAsStream("UseCookiesSessionRule.json");
        Scanner s = new Scanner(inputStream).useDelimiter("\\A");
        String ruleString = s.hasNext() ? s.next() : "";
        return new JSONObject(new JSONTokener(ruleString));
    }

    SessionRulesMarshaller()
    {
        try
        {
            String json = BurpExtender.callbacks.saveConfigAsJson("target.scope");
            targetScope = new JSONObject(new JSONTokener(json))
                    .getJSONObject("target")
                    .getJSONObject("scope");

            json = BurpExtender.callbacks.saveConfigAsJson("project_options.sessions.session_handling_rules");
            root = new JSONObject(new JSONTokener(json));
            sessionHandlingRules = root.getJSONObject("project_options")
                    .getJSONObject("sessions")
                    .getJSONObject("session_handling_rules")
                    .getJSONArray("rules");
            for (int i = 0; i < sessionHandlingRules.length(); i++)
            {
                rules.add(new Rule(sessionHandlingRules.getJSONObject(i)));
            }
        }
        catch(JSONException ex)
        {
            ex.printStackTrace(new PrintStream(BurpExtender.callbacks.getStderr()));
        }
    }

    List<String> getRulesForRequest(IRequestInfo request)
    {
        List<String> rc = new ArrayList<>();
        for (Rule rule : rules)
        {
            try
            {
                if(rule.getName().equals("Replicator use cookies"))
                {
                    continue;
                }
                if (rule.matchesRequest(request))
                {
                    rc.add(rule.getName());
                }
            }
            catch(JSONException ex)
            {
                ex.printStackTrace(new PrintStream(BurpExtender.callbacks.getStderr()));
            }
        }
        return rc;
    }

    Rule getRuleByName(String name) throws JSONException
    {
        for (Rule rule : rules)
        {
            if(rule.getName().equals(name))
            {
                return rule;
            }
        }
        return null;
    }

    class Rule
    {
        JSONObject json;

        Rule(JSONObject json) throws JSONException
        {
            this.json = json;
        }

        String getName() throws JSONException {
            return json.getString("description");
        }

        boolean matchesRequest(IRequestInfo request) throws JSONException
        {
            return isEnabled()
                    && matchesTool("Extender")
                    && matchesIParams(request.getParameters())
                    && matchesUrl(request.getUrl());
        }

        boolean isEnabled() throws JSONException
        {
            return json.getBoolean("enabled");
        }

        boolean matchesTool(String tool) throws JSONException
        {
            JSONArray toolsScope = (JSONArray) json.get("tools_scope");
            for (int i = 0; i < toolsScope.length(); i++)
            {
                if (toolsScope.get(i).equals(tool))
                {
                    return true;
                }
            }
            return false;
        }

        boolean matchesIParams(List<IParameter> params) throws JSONException
        {
            List<String> paramNames = new ArrayList<>();
            for(IParameter param : params)
            {
                paramNames.add(param.getName());
            }
            return matchesParams(paramNames);
        }

        boolean matchesParams(List<String> params) throws JSONException
        {
            if(!json.getBoolean("restrict_scope_to_named_params"))
            {
                return true;
            }
            JSONArray namedParams = json.getJSONArray("named_params");
            for (int i = 0; i < namedParams.length(); i++)
            {
                if (params.contains(namedParams.get(i)))
                {
                    return true;
                }
            }
            return false;
        }

        boolean matchesUrl(URL url) throws JSONException
        {
            JSONArray includeInScope;
            JSONArray excludeFromScope;

            String urlScope = json.getString("url_scope");
            if(urlScope.equals("all"))
            {
                return true;
            }
            else if(urlScope.equals("target"))
            {
                includeInScope = targetScope.getJSONArray("include");
                excludeFromScope = targetScope.getJSONArray("exclude");
            }
            else if(urlScope.equals("custom"))
            {
                includeInScope = json.getJSONArray("include_in_scope");
                excludeFromScope = json.getJSONArray("exclude_from_scope");
            }
            else
            {
                throw new JSONException("Invalid url_scope: " + urlScope);
            }

            boolean any_include_matches = false;
            for (int i = 0; i < includeInScope.length(); i++)
            {
                if(scopeMatchesUrl(includeInScope.getJSONObject(i), url))
                {
                    any_include_matches = true;
                    break;
                }
            }
            if(!any_include_matches)
            {
                return false;
            }

            for (int i = 0; i < excludeFromScope.length(); i++)
            {
                if(scopeMatchesUrl(excludeFromScope.getJSONObject(i), url))
                {
                    return false;
                }
            }

            return true;
        }

        boolean scopeMatchesUrl(JSONObject scope, URL url) throws JSONException
        {
            if(!scope.getBoolean("enabled"))
            {
                return false;
            }

            // Simplified scope
            if(scope.has("prefix"))
            {
                return url.toString().startsWith(scope.getString("prefix"));
            }

            // Advanced scope
            if(scope.has("host"))
            {
                String host = scope.getString("host");
                if (isIpAddress(host))
                {
                    // TBD: handle IP address
                }
                else if (!Pattern.compile(host).matcher(url.getHost()).matches())
                {
                    return false;
                }
            }

            if(scope.has("port") && !Pattern.compile(scope.getString("port")).matcher(Integer.toString(url.getPort())).matches())
            {
                return false;
            }

            if(scope.has("file") && !Pattern.compile(scope.getString("file")).matcher(url.getFile()).matches())
            {
                return false;
            }

            if(scope.has("protocol"))
            {
                String protocol = scope.getString("protocol");
                if (!protocol.equals("any") && !protocol.equals(url.getProtocol()))
                {
                    return false;
                }
            }

            return true;
        }

        boolean isIpAddress(String input)
        {
            return Pattern.compile("^\\d+\\.\\d+\\.\\d+\\.\\d+$").matcher(input).matches();
        }

        void extractMacros(Set<Long> macros) throws JSONException
        {
            JSONArray actions = json.getJSONArray("actions");
            for(int i = 0; i < actions.length(); i++)
            {
                JSONObject action = actions.getJSONObject(i);
                if(action.has("macro_serial_number"))
                {
                    macros.add(action.getLong("macro_serial_number"));
                }
            }
        }

        void changeTarget(String oldHost, int oldPort, String newHost, int newPort) throws JSONException
        {
            if(!json.getString("url_scope").equals("custom"))
            {
                return;
            }

            JSONArray includeInScope = json.getJSONArray("include_in_scope");
            for (int i = 0; i < includeInScope.length(); i++)
            {
                changeScopeTarget(includeInScope.getJSONObject(i), oldHost, oldPort, newHost, newPort);
            }

            JSONArray excludeFromScope = json.getJSONArray("exclude_from_scope");
            for (int i = 0; i < excludeFromScope.length(); i++)
            {
                changeScopeTarget(excludeFromScope.getJSONObject(i), oldHost, oldPort, newHost, newPort);
            }
        }

        void changeScopeTarget(JSONObject scope, String oldHost, int oldPort, String newHost, int newPort) throws JSONException
        {
            // Simplified scope
            if(scope.has("prefix"))
            {
                scope.put("prefix", scope.getString("prefix").replace(String.format("://%s:%d", oldHost, oldPort), String.format("://%s:%d", newHost, newPort)));
                return;
            }

            // Advanced scope
            if(scope.getString("host").equals(oldHost) && scope.getInt("port") == oldPort)
            {
                scope.put("host", newHost);
                scope.put("port", newPort);
            }
        }

    }

}
