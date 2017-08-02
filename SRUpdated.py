import json, random
from uuid import uuid4 as guid

registry = json.load(open("serviceregistry.json", "r"))
copy_registry = {"services": []}
for service in registry["services"]:
    print("Handling service '{}'".format(service["serviceDescription"]["serviceDescriptionTitle"]))
    dataset = service["serviceDescription"]["serviceDataDescription"][0].get("dataset", None)
    if dataset is not None:
        for setti in dataset:
            for purpose in setti["purpose"]:
                template =  {
                             "purpose_id": str(guid()) ,
                             "title": purpose,
                             "selected": "False",
                             "required": "False",
                             "requirement_tier": random.randrange(4)+1,
                             "url": "String"
                            }
                print(json.dumps(template, indent=2))
#            setti["purpose"] = storage
    
#print(json.dumps(registry, indent=2))
