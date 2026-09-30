"""Mock 'open a pull request' target. Records the call, never touches GitHub."""
import json, os, time, uuid
import boto3

table = boto3.resource("dynamodb").Table(os.environ["LEDGER"])


def handler(event, context):
    # Gateway passes the tool arguments as the event. Nothing here knows who the caller is;
    # that is the point: identity is decided before this function is ever invoked.
    item = {
        "id": str(uuid.uuid4()),
        "at": int(time.time()),
        "repo": event.get("repo"),
        "title": event.get("title"),
        "requested_by": event.get("requested_by", "unknown"),
    }
    table.put_item(Item=item)
    print(json.dumps({"opened_pr": item}))
    return {"pr": f"https://example.invalid/{item['repo']}/pull/{item['id'][:6]}", "repo": item["repo"]}
