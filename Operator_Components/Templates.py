# -*- coding: utf-8 -*-
from time import time
import logging
debug_log = logging.getLogger("debug")

Consent_form_Out = {  # From Operator_CR to UI
    "source": {
        "service_id": "String",
        "rs_id": "String",
        "dataset": [
            {
                "dataset_id": "String",
                "title": "String",
                "description": "String",
                "keyword": [],
                "publisher": "String",
                "distribution": {
                    "distribution_id": "String",
                    "access_url": "String"
                },
                "component_specification_label": "String",
                "selected": True
            }
        ]
    },
    "sink": {
        "service_id": "String",
        "dataset": [
            {
                "datase_id": "String",
                "title": "String",
                "description": "String",
                "keyword": [],
                "publisher": "String",
                "purposes": [

                    {
                        "title": "All your cats are belong to us",
                        "selected": True,
                        "required": True
                    },
                    {
                        "title": "Something random",
                        "selected": True,
                        "required": True
                    }
                ]
            }
        ]
    }
}

import logging
from json import dumps
class Sequences:
    def __init__(self, name):
        """

        :param name:
        """
        self.logger = logging.getLogger("sequence")
        self.name = name

    def send_to(self, to, msg=""):
        return self.seq_tool(msg, to, )

    def reply_to(self, to, msg=""):
        return self.seq_tool(msg, to, dotted=True)

    def task(self, content):

        return self.seq_tool(msg=content, box=False, to=self.name)

    def seq_tool(self, msg=None, to="Change_Me", box=False, dotted=False):

        if box:
            form = 'Note over {}: {}'.format(self.name, msg)
            return self.seq_form(form, )
        elif dotted:
            form = "{}-->{}: {}".format(self.name, to, msg)
            return self.seq_form(form)
        else:
            form = "{}->{}: {}".format(self.name, to, msg)
            return self.seq_form(form)

    def seq_form(self, line):
        self.logger.info(dumps({"seq": line, "time": time()}))
        return {"seq": {}}
