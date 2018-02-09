package burp;

import javax.swing.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

public class Menu extends JMenu
{
    JMenuItem developerView;
    JMenuItem testerView;

    public Menu(BurpExtender burpExtender)
    {
        super("Replicator");

        ItemListener itemListener = new ItemListener()
        {
            @Override
            public void itemStateChanged(ItemEvent e)
            {
                if(e.getStateChange() == ItemEvent.SELECTED)
                {
                    for(int i = 0; i < getItemCount(); i++)
                    {
                        JMenuItem menuItem = getItem(i);
                        if(menuItem != e.getSource())
                        {
                            menuItem.setSelected(false);
                        }
                    }
                    byte viewType = developerView.isSelected() ? BurpExtender.DEVELOPER_VIEW : BurpExtender.TESTER_VIEW;
                    burpExtender.callbacks.saveExtensionSetting("viewType", Integer.toString(viewType));
                    burpExtender.setViewType(viewType);
                }
            }
        };

        developerView = new JCheckBoxMenuItem("Developer view", true);
        developerView.addItemListener(itemListener);
        add(developerView);

        testerView = new JCheckBoxMenuItem("Tester view");
        testerView.addItemListener(itemListener);
        add(testerView);
    }

    void setViewType(byte viewType)
    {
        developerView.setSelected(viewType == BurpExtender.DEVELOPER_VIEW);
        testerView.setSelected(viewType == BurpExtender.TESTER_VIEW);
    }
}
