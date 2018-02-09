package burp;

import java.io.PrintWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


class IssueChecker implements Runnable
{
    List<Issue> issues;
    ReplicatorPanel replicatorPanel;
    boolean terminating = false;
    IBurpCollaboratorClientContext collaborator;
    final static int POLL_INTERVAL = 5000;

    IssueChecker(List<Issue> issues, ReplicatorPanel replicatorPanel)
    {
        this.issues = issues;
        this.replicatorPanel = replicatorPanel;
    }

    class PendingCollaboratorIssue
    {
        Issue issue;
        Instant probeTime;
        String interactionId;

        public PendingCollaboratorIssue(Issue issue)
        {
            this.issue = issue;
            this.probeTime = Instant.now();
        }

        boolean isExpired()
        {
            return probeTime.plusSeconds(issue.collaboratorTimeout).compareTo(Instant.now()) > 0;
        }

        String getPayload()
        {
            interactionId = collaborator.generatePayload(false);
            return interactionId + "." + collaborator.getCollaboratorServerLocation();
        }
    }

    @Override
    public void run() {
        List<PendingCollaboratorIssue> pendingCollaboratorIssues = new ArrayList<>();

        if(!replicatorPanel.loggedIn)
        {
            try
            {
                MacrosMarshaller.Macro macro = new MacrosMarshaller().getMacroByName(replicatorPanel.optionsPanel.getLoginMacro());
                MacroRunner.runMacro(macro, replicatorPanel);
                replicatorPanel.loggedIn = true;
            } catch (Exception ex)
            {
                ex.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStderr()));
            }
        }

        for(Issue issue : issues)
        {
            if(terminating)
            {
                break;
            }

            issue.startTest();
            byte[] request = issue.getRequestWithIdentity();
            if(issue.detectionMethod == Issue.DETECTION_COLLABORATOR)
            {
                if(collaborator == null)
                {
                    collaborator = BurpExtender.callbacks.createBurpCollaboratorClientContext();
                }
                PendingCollaboratorIssue pendingCollaboratorIssue = new PendingCollaboratorIssue(issue);
                String requestString = new String(request);
                Matcher matcher = Pattern.compile(issue.collaboratorReplace).matcher(requestString);
                if(!matcher.find())
                {
                    issue.finishTest(Issue.TEST_ERROR);
                    continue;
                }
                String payload = pendingCollaboratorIssue.getPayload();
                request = requestString.replaceAll(issue.collaboratorReplace, payload).getBytes();
                pendingCollaboratorIssues.add(pendingCollaboratorIssue);
            }

            IHttpRequestResponse response = BurpExtender.callbacks.makeHttpRequest(issue.getHttpService(), request);
            issue.response = response.getResponse();

            if(issue == replicatorPanel.optionsPanel.currentIssue)
            {
                replicatorPanel.responseEditor.setMessage(issue.response == null ? OptionsPanel.EMPTY_MESSAGE : issue.response, false);
            }

            byte testStatus;
            if(issue.response == null)
            {
                testStatus = Issue.TEST_ERROR;
                issue.finishTest(testStatus);
                continue;
            }

            if(issue.detectionMethod == Issue.DETECTION_GREP)
            {
                String strResponse = new String(issue.response);
                if (issue.grepExpression == null || issue.grepExpression.isEmpty())
                {
                    testStatus = Issue.TEST_ERROR;
                }
                else
                {
                    Matcher matcher = Pattern.compile(issue.grepExpression).matcher(strResponse);
                    testStatus = matcher.find() ? Issue.TEST_DETECTED : Issue.TEST_NOT_DETECTED;
                }
                issue.finishTest(testStatus);
            }
        }

        while(!pendingCollaboratorIssues.isEmpty())
        {
            try
            {
                Thread.sleep(POLL_INTERVAL);
            }
            catch (InterruptedException e)
            {
                // do nothing
            }

            for (IBurpCollaboratorInteraction interaction : collaborator.fetchAllCollaboratorInteractions())
            {
                String interactionId = interaction.getProperty("interaction_id");
                for (Iterator<PendingCollaboratorIssue> iterator = pendingCollaboratorIssues.iterator(); iterator.hasNext();)
                {
                    PendingCollaboratorIssue pendingCollaboratorIssue = iterator.next();
                    if(pendingCollaboratorIssue.interactionId.equals(interactionId))
                    {
                        pendingCollaboratorIssue.issue.finishTest(Issue.TEST_DETECTED);
                        iterator.remove();
                    }
                }
            }

            for (Iterator<PendingCollaboratorIssue> iterator = pendingCollaboratorIssues.iterator(); iterator.hasNext();)
            {
                PendingCollaboratorIssue pendingCollaboratorIssue = iterator.next();
                if(pendingCollaboratorIssue.isExpired())
                {
                    pendingCollaboratorIssue.issue.finishTest(Issue.TEST_NOT_DETECTED);
                    iterator.remove();
                }
            }
        }

        replicatorPanel.burpExtender.issueChecker = null;
    }
}
