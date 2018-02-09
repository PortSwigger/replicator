package burp;

import java.util.Date;


public class DeleteCookie implements ICookie
{
    String domain;
    String name;
    String path;

    public DeleteCookie(String domain, String name, String path)
    {
        this.domain = domain;
        this.name = name;
        this.path = path;
    }

    @Override
    public String getDomain()
    {
        return domain;
    }

    @Override
    public String getPath()
    {
        return path;
    }

    @Override
    public Date getExpiration()
    {
        return null;
    }

    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public String getValue()
    {
        return null;
    }
}
