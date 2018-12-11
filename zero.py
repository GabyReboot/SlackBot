import json, os
from slackclient import SlackClient



jsonData = ''' {
  "type": "bundle",
  "id": "bundle--44af6c39-c09b-49c5-9de2-394224b04982",
  "spec_version": "2.0",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--33fe3b22-0201-47cf-85d0-97c02164528d",
      "created": "2014-05-08T09:00:00.000Z",
      "modified": "2014-05-08T09:00:00.000Z",
      "name": "IP Address for known C2 channel",
      "labels": [
        "malicious-activity"
      ],
      "pattern": "[ipv4-addr:value = '10.0.0.0']",
      "valid_from": "2014-05-08T09:00:00.000000Z"
    }
  ]
}
''' 

toPy = json.loads(jsonData)
data = toPy['objects'][0]


def digest(meat):

    valid_from = meat['valid_from']
    type = meat['type']
    id = meat['id']
    created = meat['created']
    modified = meat['modified']
    name = meat['name']
    labels = meat['labels'][0]
    pattern = meat['pattern']
    valid_from = meat['valid_from']

    return '''
    *Type*: {}
    *Id*: {}
    *Created*: {}
    *Modified*: {}  
    *Name*: {}  
    *Labels*: {}
    *Pattern*: {}
    *Valid from*: {}
     '''.format(type, id, created, modified, name, labels, pattern, valid_from)
    
pp = digest(data)



#slack api
# Export the Slack token with the name 'SLACK_BOT_TOKEN:' in command line. Syntax is as follows
# export SLACK_BOT_TOKEN='your bot user access token here'
slack_token = os.environ["SLACK_BOT_TOKEN"]
sc = SlackClient(slack_token)
print(pp)
sc.api_call(
  "chat.postMessage",
  channel="CENCUCHLH",
  mrkdown= "true",
  text=pp
)

