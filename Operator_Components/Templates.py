# -*- coding: utf-8 -*-
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
