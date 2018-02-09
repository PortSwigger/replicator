package burp;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.imageio.ImageIO;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;


public class JsonMarshaller
{
    static int JSON_FILE_VERSION = 1;
    List<String> warnings = new ArrayList<>();
    SessionRulesMarshaller sessionRulesMarshaller = new SessionRulesMarshaller();
    MacrosMarshaller macrosMarshaller = new MacrosMarshaller();

    JSONObject marshall(ReplicatorPanel replicatorPanel) throws JSONException
    {
        JSONObject json = new JSONObject();
        json.put("burp_replicator_file_version", JSON_FILE_VERSION);
        String loginMacro = replicatorPanel.optionsPanel.getLoginMacro();
        json.put("login_macro", loginMacro);
        json.put("notes", replicatorPanel.optionsPanel.jNotes.getText());
        json.put("config", replicatorPanel.config);

        if(replicatorPanel.logo != null)
        {
            try
            {
                ByteArrayOutputStream logoStream = new ByteArrayOutputStream();
                ImageIO.write(replicatorPanel.logo, "png", logoStream);
                json.put("logo", Base64.getEncoder().encodeToString(logoStream.toByteArray()));
            }
            catch (Exception e)
            {
                e.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStderr()));
            }
        }

        Collection<String> rules = getAllRules(replicatorPanel.issueTableModel.issues);
        Collection<Long> macros = getAllMacros(rules);
        MacrosMarshaller.Macro jsonLoginMacro = macrosMarshaller.getMacroByName(loginMacro);
        if(jsonLoginMacro != null)
        {
            macros.add(jsonLoginMacro.getSerial());
        }

        json.put("session_rules", marshallRules(rules));
        json.put("macros", marshallMacros(macros));
        json.put("issues", marshallIssueTableModel(replicatorPanel.issueTableModel));
        return json;
    }

    Collection<String> getAllRules(Iterable<Issue> issues)
    {
        Set<String> rules = new HashSet<>();
        for(Issue issue : issues)
        {
            for(String ruleName : issue.sessionHandlingRules)
            {
                rules.add(ruleName);
            }
        }
        return rules;
    }

    private JSONArray marshallRules(Iterable<String> rules) throws JSONException
    {
        JSONArray rc = new JSONArray();
        for(String ruleName : rules)
        {
            rc.put(sessionRulesMarshaller.getRuleByName(ruleName).json);
        }
        return rc;
    }

    Collection<Long> getAllMacros(Iterable<String> rules) throws JSONException
    {
        Set<Long> macros = new HashSet<>();
        for(String ruleName : rules)
        {
            SessionRulesMarshaller.Rule rule = sessionRulesMarshaller.getRuleByName(ruleName);
            rule.extractMacros(macros);
        }
        return macros;
    }

    private JSONArray marshallMacros(Iterable<Long> macros) throws JSONException
    {
        JSONArray rc = new JSONArray();
        for(Long macroSerial : macros)
        {
            rc.put(macrosMarshaller.getMacroBySerial(macroSerial).json);
        }
        return rc;
    }


    private JSONArray marshallIssueTableModel(IssueTableModel issueTableModel)
    {
        JSONArray rc = new JSONArray();
        for(Issue issue : issueTableModel.issues)
        {
            try
            {
                rc.put(marshallIssue(issue));
            }
            catch(Exception ex)
            {
                warnings.add(ex.toString());
                ex.printStackTrace(new PrintStream(BurpExtender.callbacks.getStderr()));
            }
        }
        return rc;
    }

    private JSONObject marshallIssue(Issue issue) throws JSONException
    {
        JSONObject data = new JSONObject();
        data.put("id", issue.id);
        data.put("issue", issue.issue);
        data.put("path", issue.path);
        data.put("parameter", issue.parameter);
        data.put("status", issue.status);
        data.put("everVulnerable", issue.everVulnerable);
        data.put("notes", issue.notes);
        data.put("detection_method", issue.detectionMethod);
        if(issue.detectionMethod == Issue.DETECTION_GREP)
        {
            data.put("grep_expression", issue.grepExpression);
        }
        if(issue.detectionMethod == Issue.DETECTION_COLLABORATOR);
        {
            data.put("collaborator_replace", issue.collaboratorReplace);
            data.put("collaborator_timeout", issue.collaboratorTimeout);
        }
        data.put("request", new String(issue.request));
        data.put("response", new String(issue.response));
        data.put("url", issue.url);
        JSONArray sessionRules = new JSONArray();
        for(String rule : issue.sessionHandlingRules)
        {
            sessionRules.put(rule);
        }
        data.put("session_rules", sessionRules);
        return data;
    }

    void unmarshall(JSONObject data, ReplicatorPanel replicatorPanel) throws Exception
    {
        if(!data.has("burp_replicator_file_version"))
        {
            throw new Exception("This is not a Replicator file.");
        }
        if(data.getInt("burp_replicator_file_version") > JSON_FILE_VERSION)
        {
            warnings.add("Replicator file was created with a newer version of Replicator. Some features may not work.");
        }
        unmarshallIssueTableModel(replicatorPanel.issueTableModel, data.getJSONArray("issues"));

        replicatorPanel.optionsPanel.setLoginMacro(data.optString("login_macro"));
        replicatorPanel.optionsPanel.jNotes.setText(data.optString("notes"));
        replicatorPanel.config = data.optString("config");

        if(data.has("logo"))
        {
            byte[] logoBytes = Base64.getDecoder().decode(data.getString("logo"));
            replicatorPanel.optionsPanel.setLogo(new ByteArrayInputStream(logoBytes));
        }
        else
        {
            replicatorPanel.logo = null;
            replicatorPanel.optionsPanel.setViewType(replicatorPanel.viewType);
        }

        new MacrosMarshaller().setProjectMacros(data.getJSONArray("macros"));
        new SessionRulesMarshaller().setProjectSessionRules(data.getJSONArray("session_rules"));
    }

    void unmarshallIssueTableModel(IssueTableModel issueTableModel, JSONArray data) throws JSONException
    {
        issueTableModel.issues = new ArrayList<Issue>();
        for(int i = 0; i < data.length(); i++)
        {
            try
            {
                issueTableModel.addIssue(unmarshallIssue(data.getJSONObject(i)));
            }
            catch(Exception ex)
            {
                warnings.add(ex.toString());
                ex.printStackTrace(new PrintStream(BurpExtender.callbacks.getStderr()));
            }
        }
        issueTableModel.fireTableDataChanged();
    }


    private Issue unmarshallIssue(JSONObject data) throws JSONException, MalformedURLException
    {
        Issue issue = new Issue();
        issue.id = data.optString("id");
        issue.issue = data.optString("issue");
        issue.path = data.optString("path");
        issue.parameter = data.optString("parameter");
        issue.status = (byte) data.optInt("status");
        issue.everVulnerable = data.optBoolean("everVulnerable");
        issue.notes = data.optString("notes");
        issue.detectionMethod = (byte) data.optInt("detection_method");
        if(issue.detectionMethod == Issue.DETECTION_GREP)
        {
            issue.grepExpression = data.optString("grep_expression");
        }
        if(issue.detectionMethod == Issue.DETECTION_COLLABORATOR)
        {
            issue.collaboratorReplace = data.optString("collaborator_replace");
            issue.collaboratorTimeout = data.optInt("collaborator_timeout");
        }

        issue.url = new URL(data.getString("url")); // mandatory
        issue.request = data.getString("request").getBytes(); // mandatory
        if(data.has("response"))
        {
            issue.response = data.getString("response").getBytes();
        }
        JSONArray sessionRules = data.getJSONArray("session_rules");
        for(int i = 0; i < sessionRules.length(); i++)
        {
            issue.sessionHandlingRules.add(sessionRules.getString(i));
        }
        return issue;
    }

}
