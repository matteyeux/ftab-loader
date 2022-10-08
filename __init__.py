from binaryninjaui import UIContext, UIContextNotification
from .ftab import FtabView

FtabView.register()


class UINotification(UIContextNotification):
    def __init__(self):
        UIContextNotification.__init__(self)
        UIContext.registerNotification(self)

    def __del__(self):
        UIContext.unregisterNotification(self)

    def OnAfterOpenFile(self, context, file, frame):
        if "Raw" not in frame.getCurrentView():
            return

        # close latest tab which is the actual ftab file we loaded
        context.closeTab(context.getTabs()[-1])

notif = UINotification()
