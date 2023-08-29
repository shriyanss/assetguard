from flask import *
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import argparse
import threading
import sqlite3
import os
import re

# import custom files
import DbManager

# argument parser
parser = argparse.ArgumentParser()

parser.add_argument('--no-web', help="Don't start web interface. Use interactive mode instead",
                    default=False, dest="web", action="store_true")
parser.add_argument(
    "--ip", help="Host to start web interface on", dest="ip", default="0.0.0.0")
parser.add_argument(
    "-p", "--port", help="Port to start web interface on", dest="port", default=8899)
parser.add_argument(
    "--usrnm", help="Username for HTTP Basic Auth (default 'admin')", dest="usrnm", default="admin")
parser.add_argument(
    "--passwd", help="Password for HTTP Basic Auth (default 'admin')", dest="passwd", default="admin")
parser.add_argument("--new-db", help="Create a new database",
                    dest="new_db", action="store_true", default=False)
parser.add_argument("--db-file", help="Location of the database. Enter a new if doesn't exists (default target_data/assetguard.sqlite)",
                    dest="db_file", default="target_data/assetguard.sqlite")

args = parser.parse_args()


def check_regex_pattern(input_string, regex_pattern):
    """
    `check_regex_pattern` checks if the provided string follows the provided regex
    """
    # Use re.match() to check if the string follows the regex pattern
    match = re.match(regex_pattern, input_string)

    # Check if there is a match and the match spans the entire string
    if match and match.span()[1] == len(input_string):
        return True
    else:
        return False


class Server:
    """
    `Server` class manages the web application for the AssetGuard
    """

    def __init__(self):
        self.app = Flask(__name__)
        self.auth = HTTPBasicAuth()
        self.db_manager = DbManager.Manager(db_file)

        @self.auth.verify_password
        def verify_password(username, password):
            if username and password:
                if username == args.usrnm and password == args.passwd:
                    return True
                else:
                    self.db_manager.logEvent(
                        [("invalid_authentication_attempt", f"Invalid authentication attempt from {request.remote_addr} with username as `{username}` and password as `{password}`")])
                    return False
            self.db_manager.logEvent(
                [("invalid_authentication_attempt", f"Invalid authentication attempt from {request.remote_addr}")])
            return False

        # for root

        @self.app.route("/")
        @self.auth.login_required
        def handleIndex():
            return render_template("index.html")

        # for web interface to add targets

        @self.app.route('/add_targets', methods=["GET", "POST"])
        @self.auth.login_required
        def handleReturnAddTargets():
            if request.method == "GET":
                return render_template("targets/add_targets.html")
            elif request.method == "POST":
                data = request.form

                if data["type"] == "single_domain":
                    domain = data["domain"]
                    program_url = data["program_url"]
                    enabled = int(data["enabled"])

                    # check if the domain already exists
                    if len(self.db_manager.execute_select_query("""SELECT * FROM domains WHERE domain=?""", (domain,))) != 0:
                        return render_template("targets/add_targets.html", message=f"`{domain}` already exists")

                    # check if the given domain matches the regex of domain
                    if check_regex_pattern(domain, "^[a-zA-Z_0-9\.]+\.[a-z]{2,}$") == False:
                        return render_template("targets/add_targets.html", program_url=program_url, domain=domain, message="Please enter a valid domain name")

                    # check if the given program url matches the regex of URL
                    if check_regex_pattern(program_url, "^https?://[a-zA-Z_0-9\.]+\.[a-z]{2,}/?[a-zA-Z0-9_\.\-]*$") == False:
                        return render_template("targets/add_targets.html", program_url=program_url, domain=domain, message="Please enter a valid program URL")

                    self.db_manager.addTargetDomain(
                        domain, program_url, enabled)

                    self.db_manager.logEvent(
                        [("domain_added", f"{domain} added")])

                    return render_template("targets/add_targets.html",  message=f"Target '{domain}' added sucessfully")

        # to list targets available in the database

        @self.app.route("/list_targets")
        @self.auth.login_required
        def handleListTargets(message=""):
            table = """<table>
                <tr>
                    <th>Target Domain</th>
                    <th>Program URL</th>
                    <th>Enabled</th>
                    <th>Action</th>
                </tr>
            """

            target_data = self.db_manager.execute_select_query(
                "SELECT * FROM domains;", ())

            if len(target_data) == 0:
                return render_template("targets/list_targets.html", table="No domains found")

            for row in target_data:
                if row[2] > 0:
                    enabled = "&#10004;"
                else:
                    enabled = ""
                table += f"""
                    <tr>
                        <td style="text-align: center;">{row[0]}</td>
                        <td style="text-align: center;"><a href="{row[1]}" target="_blank">{row[1]}</a></td>
                        <td style="text-align: center;">{enabled}</td>
                        <td style="text-align: center;">
                            <a href="/delete?type=domain&domain={row[0]}">Delete</a>
                            <a href="/enable?type=domain&domain={row[0]}">Enable/Disable</a>
                        </td>
                    </tr>
                """

            table += "</table>"

            return render_template("targets/list_targets.html", table=table, message=message)

        # to delete a target from the

        @self.app.route("/delete", methods=["GET", "POST"])
        @self.auth.login_required
        def handleDeleteData():
            if request.method == "GET":
                delete_type = request.args.get("type")
                if delete_type == "domain":
                    domain = request.args.get("domain")
                    return render_template("utility/delete.html", message=f"Are you sure want to delete domain '{domain}'?", back_location="/list_targets", action=f"/delete?type=domain&domain={domain}")
                elif delete_type == "logs":
                    return render_template("utility/delete.html", message=f"Are you sure want to delete all logs?", back_location="/logs", action=f"/delete?type=logs")
                elif delete_type == "command":
                    cmd = self.db_manager.execute_select_query("SELECT command FROM commands WHERE id=?", (request.args.get("cmd_id"),) )[0][0]
                    tool = self.db_manager.execute_select_query("SELECT tool FROM commands WHERE id=?", (request.args.get("cmd_id"),) )[0][0]
                    return render_template("utility/delete.html", message=f"Are you sure want to delete the command `<code>{cmd}</code>` for tool `{tool}`", back_location="/cmds", action=f"""/delete?type=command&cmd_id={request.args.get("cmd_id")}""")
            elif request.method == "POST":
                if request.args.get("type") == "domain":
                    domain = request.args.get("domain")
                    self.db_manager.execute_other_query(
                        "DELETE FROM domains WHERE domain=?; ",
                        (domain,)
                    )
                    self.db_manager.logEvent(
                        [("delete_domain", f"{domain} deleted")])
                    return render_template("targets/list_targets.html", message=f"`{domain}` deleted successfully")
                elif request.args.get("type") == "logs":
                    self.db_manager.execute_other_query("DELETE FROM logs", ())
                    return render_template("logs/logs.html", message=f"Logs deleted successfully", table=createLogTable())
                elif request.args.get("type") == "command":
                    cmd = self.db_manager.execute_select_query("SELECT * FROM commands WHERE id=?", (request.args.get("cmd_id"),))
                    self.db_manager.execute_select_query("DELETE FROM commands WHERE id=?", (request.args.get("cmd_id")))
                    self.db_manager.logEvent([(
                        "delete_command",
                        f"""Command `{cmd[2]}` deleted for {cmd[1]} and file command = {cmd[3]}"""
                    )])

                    return redirect("/cmds")

        @self.app.route("/enable")
        @self.auth.login_required
        def handleChangeEnable():
            if request.args.get("type") == "domain":
                current_state = int(self.db_manager.execute_select_query(
                    "SELECT enabled FROM domains WHERE domain=?; ", (request.args.get('domain'),))[0][0])
                if current_state == 0:
                    self.db_manager.execute_other_query(
                        "UPDATE domains SET enabled=1 WHERE domain=?; ",
                        (
                            request.args.get('domain'),
                        )
                    )

                    self.db_manager.logEvent([("update_domain_enable",
                                               f"{request.args.get('domain')} enabled")])

                    message = f"'{request.args.get('domain')}' successfully enabled"
                else:
                    self.db_manager.execute_other_query(
                        "UPDATE domains SET enabled=0 WHERE domain=?; ",
                        (
                            request.args.get('domain'),
                        )
                    )
                    self.db_manager.logEvent(
                        [("update_domain_enable",
                         f"{request.args.get('domain')} disabled")]
                    )
                    message = f"'{request.args.get('domain')}' successfully disabled"

                return handleListTargets(message=message)

        # to return the list of available tools

        @self.app.route("/tools", methods=["GET", "POST"])
        @self.auth.login_required
        def handleToolList():
            if request.method == "GET":
                amass = self.db_manager.execute_select_query(
                    "SELECT * FROM tools WHERE name='amass'; ", ())[0]
                subfinder = self.db_manager.execute_select_query(
                    "SELECT * FROM tools WHERE name='subfinder'; ", ())[0]

                # check if the tool is enabled or not
                if amass[2] > 0:
                    amass_checked = "checked"
                else:
                    amass_checked = ""
                if subfinder[2] > 0:
                    subfinder_checked = "checked"
                else:
                    subfinder_checked = ""

                # check the executable binary path for the tool
                amass_binary = amass[1]
                subfinder_binary = subfinder[1]

                return render_template("tools/tools.html",
                                       subfinder_checked=subfinder_checked,
                                       amass_checked=amass_checked,
                                       amass_binary=amass_binary,
                                       subfinder_binary=subfinder_binary
                                       )
            elif request.method == "POST":
                data = request.form

                amass = int(data.get('amass_enabled', '0'))
                subfinder = int(data.get('subfinder_enabled', '0'))

                self.db_manager.execute_multi_query("UPDATE tools SET enabled=? WHERE name=?;", (
                    [amass, "amass"],
                    [subfinder, "subfinder"]
                ))

                self.db_manager.logEvent(
                    [("target_added", "A new target domain.com was added")])

                return render_template("tools/tools.html", message="<script>location.href = location.href;</script>")

        @self.app.route("/cmds", methods=["GET", "POST"])
        @self.auth.login_required
        def handleCmds():
            def generateCommandTable():
                # get the available command from the table
                commands = self.db_manager.execute_select_query(
                    "SELECT * FROM commands; ", ())

                table = """ 
                    <table>
                        <tr>
                            <th>Tool Name</th>
                            <th>Command</th>
                            <th>Command for file</th>
                            <th>Action</th>
                        </tr>
                """

                for row in commands:
                    if row[3] > 0:
                        command_for_file = "&#10004;"
                    else:
                        command_for_file = ""

                    table += f""" 
                        <tr>
                            <td style="text-align: center;">{row[1]}</td>
                            <td style="text-align: center;">
                                <form action="/cmds" method="POST">
                                    <textarea name="command">{row[2]}</textarea>
                                    <input type="number" value="{row[0]}" name="id" hidden>
                                    <input type="submit" value="Update">
                                </form>
                            </td>
                            <td style="text-align: center;">{command_for_file}</td>
                            <td><a href="/delete?type=command&cmd_id={row[0]}">Delete</a></td>
                        </tr>
                    """
                table += """ 
                    </table>
                """

                return table

            if request.method == "GET":
                available_db = self.db_manager.execute_select_query("SELECT * FROM tools WHERE enabled>0; ", ())

                tools_select = ""

                for row in available_db:
                    tools_select += f""" 
                        <option value="{row[0]}">{row[0]}</option>
                    """
                return render_template("config/cmds.html", tools=generateCommandTable(), tools_list=tools_select)
            elif request.method == "POST":
                data = request.form
                id = int(data["id"])
                command = data["command"]

                self.db_manager.execute_other_query(
                    "UPDATE commands set command=? WHERE id=?;",
                    (
                        command,
                        id,
                    )
                )

                self.db_manager.logEvent(
                    [("update_command", f"Command ID `{id}` updated from to {command}")])

                return render_template("config/cmds.html",
                                       tools_message="Command updated successfully!",
                                       tools=generateCommandTable()
                                       )
        @self.app.route("/new_command", methods=["POST"])
        @self.auth.login_required
        def handleNewCommand():
            form_data = request.form

            tool_name = form_data["tool_name"]
            command = form_data["command"]

            file_command = request.form.get("file_command", "off")

            if file_command == "off":
                file_command = 0
            else:
                file_command = 1

            if tool_name == "amass" or tool_name == "subfinder":
                cmd_type = "subdomain_enum"
            else:
                cmd_type = ""
            

            self.db_manager.execute_other_query("INSERT INTO commands (tool, command, file_command, cmd_type) VALUES (?, ?, ?, ?)", (tool_name, command, file_command, cmd_type,))

            return redirect("/cmds")

        # generate logs table
        def createLogTable():
            """
            `createLogTable` reads application log, creates table, and returns it
            """
            logs = self.db_manager.execute_select_query(
                "SELECT * FROM logs ORDER BY timestamp DESC;", ())

            table = """ 
                    <table>
                        <tr>
                            <th>Event Name</th>
                            <th>Event Info</th>
                            <th>Timestamp</th>
                        </tr>
                """

            for row in logs:
                table += f"""
                        <tr>
                            <td>{row[0]}</td>
                            <td>{row[1]}</td>
                            <td>{row[2]}</td>
                        </tr>
                    """

            table += "</table>"
            return table

        @self.app.route("/logs")
        @self.auth.login_required
        def handleLogs():
            return render_template("logs/logs.html", table=createLogTable())

        def generateScheduleTable():
            schedule = self.db_manager.execute_select_query(
                "SELECT * FROM schedule", ())
            table = """ 
                        <table>
                            <tr>
                                <th>Hour of day</th>
                                <th>Minute</th>
                                <th>Day</th>
                                <th>Command</th>
                                <th>Action</th>
                            </tr>
                    """
            for row in schedule:
                command = self.db_manager.execute_select_query(
                    "SELECT command,tool FROM commands WHERE id=?", (row[4],))[0]
                table += f""" 
                            <tr>
                                <td style="text-align: center; padding: 5px 5px 5px 5px">{row[1]}</td>
                                <td style="text-align: center; padding: 5px 5px 5px 5px">{row[2]}</td>
                                <td style="text-align: center; padding: 5px 5px 5px 5px">{row[3]}</td>
                                <td style="text-align: center; padding: 5px 5px 5px 5px"><code>{command[0]}</code> <i>(Tool: {command[1]})</i></td>
                                <td style="text-align: center; padding: 5px 5px 5px 5px">
                                    <a href="#">Edit</a>
                                </td>
                            </tr>
                        """

            table += "</table>"

            return table

        @self.app.route("/scheudle", methods=["GET", "POST"])
        @self.auth.login_required
        def handleSchedule():
            if request.method == "GET":
                schedule = self.db_manager.execute_select_query(
                    "SELECT * FROM schedule", ())
                if len(schedule) == 0:
                    table = "No schedule found"
                else:
                    table = generateScheduleTable()

                return render_template("config/schedule.html", table=table)
        
        @self.app.route("/edit_schedule")
        @self.auth.login_required
        def handleEditSchedule():
            schedule_id = int(request.args.get("cmd_id"))
            schedule = self.db_manager.execute_select_query("SELECT * FROM schedule where id=?", (schedule_id,))

            # generate select menu for command
            commands = self.db_manager.execute_select_query("SELECT * FROM commands WHERE cmd_type=?", schedule[5])

            return render_template("utility/edit_schedule.html", hour=schedule[1], minute=schedule[2])

    def start_server(self):
        self.app.run(str(args.ip), int(args.port))


if __name__ == "__main__":
    global db_file
    db_file = args.db_file
    if args.new_db == True or os.path.exists("target_data/assetguard.sqlite") == False:
        if os.path.isdir("target_data") == False:
            os.mkdir("target_data")
        DbManager.Manager.createNewDB(args.db_file)
    if args.web == False:
        svr = Server()
        svr_thread = threading.Thread(target=svr.start_server)
        svr_thread.start()
