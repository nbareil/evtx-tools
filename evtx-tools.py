#! /usr/bin/env python
# /// script
# dependencies = [evtx, click]
# ///

import os
import json

import click
from evtx import PyEvtxParser

def flatten_event(data):
    event = data.get("Event")
    event.update(event.get("System"))
    del(event["System"])
    if "EventData" in event:
        event.update(event.get("EventData"))
        del(event["EventData"])
    event["TimeCreated"] = event["TimeCreated"]["#attributes"]["SystemTime"]
    event["Provider"] = event["Provider"]["#attributes"]["Name"]
    event["ProcessID"] = event["Execution"]["#attributes"]["ProcessID"]
    event["ThreadID"] = event["Execution"]["#attributes"]["ThreadID"]
    del(event["Execution"])
    del(event["#attributes"])
    return event

def filter_event(events, keep_eventid: list):
    for event in events:
        data = json.loads(event['data'])
        if data.get("Event").get("System").get("EventID") in keep_eventid:
            yield data

@click.group()
@click.option("--json", default=False, help="Output JSON output", is_flag=True)
@click.option("--verbose", default=False, help="Verbose mode", is_flag=True)
@click.pass_context
def cli(ctx, json, verbose):
    # ensure that ctx.obj exists and is a dict (in case `cli()` is called
    # by means other than the `if` block below)
    ctx.ensure_object(dict)
    ctx.obj['JSON'] = json
    ctx.obj['verbose'] = verbose

def guess_filename(fname) -> str:
    for try_filename in [fname, os.path.join("Windows", "System32", "winevt", "Logs", fname)]:
        if os.path.exists(try_filename):
            return try_filename
    raise click.BadParameter("Impossible to find Security.evtx")

@cli.command()
@click.argument("filename", required=False)
@click.pass_context
def process_exec_native(ctx, filename):
    filename = filename if filename else guess_filename("Security.evtx")
    for event in get_records(filename, [4688]):
        if ctx.obj.get("JSON"):
            click.echo(json.dumps(event))
        else:
            process_4688_event(event)


def process_4688_event(event):
    fields = [
            "TimeCreated",
            "TargetUserName",
            "NewProcessName",
            "CommandLine"
    ]
    click.echo(" ".join(map(event.get, fields)))

@cli.command()
@click.argument("filename", required=False)
@click.pass_context
def group_enum(ctx, filename):
    filename = filename if filename else guess_filename("Security.evtx")
    for event in get_records(filename, [4799]):
        if ctx.obj.get("JSON"):
            click.echo(json.dumps(event))
        else:
            fields = [
                    event["TimeCreated"],
                    "%s\\%s" % (event["SubjectDomainName"], event["SubjectUserName"]),
                    "listed",
                    "%s\\%s" % (event["TargetDomainName"], event["TargetUserName"]),
                    "with process",
                    event["CallerProcessName"]
            ]
            click.echo(" ".join(fields))


logon_failure_reasons = {
    0x0:        "Status OK.",
    0xC000005E: "There are currently no logon servers available to service the logon request.",
    0xC0000064: "User logon with misspelled or bad user account",
    0xC000006A: "User logon with misspelled or bad password",
    0xC000006D: "This is either due to a bad username or authentication information",
    0xC000006E: "Unknown user name or bad password.",
    0xC000006F: "User logon outside authorized hours",
    0xC0000070: "User logon from unauthorized workstation",
    0xC0000071: "User logon with expired password",
    0xC0000072: "User logon to account disabled by administrator",
    0xC00000DC: "Indicates the Sam Server was in the wrong state to perform the desired operation.",
    0xC0000133: "Clocks between DC and other computer too far out of sync",
    0xC000015B: "The user has not been granted the requested logon type (aka logon right) at this machine",
    0xC000018C: "The logon request failed because the trust relationship between the primary domain and the trusted domain failed.",
    0xC0000192: "An attempt was made to logon, but the Netlogon service was not started.",
    0xC0000193: "User logon with expired account",
    0xC0000224: "User is required to change password at next logon",
    0xC0000225: "Evidently a bug in Windows and not a risk",
    0xC0000234: "User logon with account locked",
    0xC00002EE: "Failure Reason: An Error occurred during Logon",
    0xC0000413: "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine.",
}

@cli.command()
@click.argument("filename", required=False)
@click.option("--machine", is_flag=True, help="Display machines to machine changes")
@click.option("--all", is_flag=True, help="Do not filter LogonTypes")
@click.pass_context
def authentications(ctx, filename, machine, all):
    filename = filename if filename else guess_filename("Security.evtx")
    for event in get_records(filename, [4624, 4625, 4648]):
        if not machine and event["TargetUserName"].endswith("$"):
            continue
        if event["EventID"] != 4648 and not all and event.get("LogonType") not in [3, 8, 10]:
            continue
        if ctx.obj.get("JSON"):
            click.echo(json.dumps(event))
        else:
            if event["EventID"] == 4625:
                fields = [
                    event["TimeCreated"],
                    "EventID=4625 ⛔",
                    "LogonType=%d" % (event["LogonType"]),
                    "%s\\%s" % (event["TargetDomainName"], event["TargetUserName"]),
                    "from",
                    event["IpAddress"],
                    "because",
                    logon_failure_reasons.get(int(event["SubStatus"], 16), "🤷")
                ]
            elif event["EventID"] == 4648:
                fields = [
                    event["TimeCreated"],
                    "EventID=4648",
                    "%s\\%s" % (event["SubjectDomainName"], event["SubjectUserName"]),
                    "logged on as",
                    "%s\\%s" % (event["TargetDomainName"], event["TargetUserName"]),
                    "with process",
                    event["ProcessName"]
                ]
            else: 
                fields = [
                    event["TimeCreated"],
                    "EventID=4624",
                    "LogonType=%d%s" % (event["LogonType"], " 🖥️ " if event["LogonType"] == 10 else ""),
                    #"%s\\%s" % (event["SubjectDomainName"], event["SubjectUserName"]),
                    #"to",
                    "%s\\%s" % (event["TargetDomainName"], event["TargetUserName"]),
                    "from",
                    event["IpAddress"]
                ]
                

            click.echo(" ".join(fields))

@cli.command()
@click.argument("filename", required=False)
@click.pass_context
def network_share(ctx, filename):
    filename = filename if filename else guess_filename("Security.evtx")
    for event in get_records(filename, [5140]):
        if ctx.obj.get("JSON"):
            click.echo(json.dumps(event))
        else:
            fields = [
                    event["TimeCreated"],
                    "%s\\%s" % (event["SubjectDomainName"], event["SubjectUserName"]),
                    "from",
                    event["IpAddress"],
                    "opened",
                    event["ShareName"]
            ]
            click.echo(" ".join(fields))

@cli.command()
@click.argument("filename", required=False)
@click.pass_context
def smbserver(ctx, filename):
    filename = filename if filename else guess_filename("Microsoft-Windows-SMBServer%4Security.evtx")
    for event in get_records(filename, [1015]):
        if ctx.obj.get("JSON"):
            click.echo(json.dumps(event))
        else:
            user_data = event.get("UserData").get("EventData")
            fields = [
                    event["TimeCreated"],
                    #user_data["ClientAddress"],
                    user_data["ClientName"]
            ]
            click.echo(" ".join(fields))

@cli.command()
@click.argument("filename", required=False)
@click.pass_context
def rdphint(ctx, filename):
    filename = filename if filename else guess_filename('Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx')
    for event in get_records(filename, [1149]):
        if ctx.obj.get("JSON"):
            click.echo(json.dumps(event))
        else:
            params = [
                    event["TimeCreated"],
                    "%s\\%s" % (event.get("UserData").get("EventXML").get("Param2"),
                        event.get("UserData").get("EventXML").get("Param1")),
                    event.get("UserData").get("EventXML").get("Param3")
            ]
            click.echo(" ".join(params))

@cli.command()
@click.argument("filename", required=False)
@click.option("--runs", required=False, is_flag=True)
@click.pass_context
def task_scheduler(ctx, filename, runs):
    filename = filename if filename else guess_filename("Microsoft-Windows-TaskScheduler%4Operational.evtx")
    selected_eventids =  [106, 141]
    if runs:
        selected_eventids += [100, 102, 200, 201]
    for event in get_records(filename, selected_eventids):
        if ctx.obj.get("JSON"):
            click.echo(json.dumps(event))
        else:
            process_task_scheduler_event(event)

def process_task_scheduler_event(event):
    event_id = event["EventID"]
    if event_id == 100:
        click.echo(" ".join([event["TimeCreated"], "TASK_RUN", event["TaskName"]]))
    elif event_id == 102:
        click.echo(" ".join([event["TimeCreated"], "TASK_FINISHED", event["TaskName"]]))
    elif event_id == 141:
        pass
    elif event_id == 106:
        click.echo(" ".join([event["TimeCreated"], "TASK_REGISTERED", event["TaskName"], event["UserContext"]]))
    elif event_id == 200:
        pass

def get_records(filename, selected_eventids):
    a = open(filename, 'rb')
    parser = PyEvtxParser(a)
    for record in filter_event(parser.records_json(), selected_eventids):
        event = flatten_event(record)
        yield event

if __name__ == "__main__":
    cli()
