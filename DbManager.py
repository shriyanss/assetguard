import sqlite3


class Manager:
    """
    `Manager` handles database related operations
    """

    def __init__(self, db_file):
        self.db_file = db_file

    def createNewDB(db_location):
        """ 
        `createNewDB` function creates a new database file
        """
        connection = sqlite3.connect(db_location)
        cursor = connection.cursor()

        # create a new table called domains that will store domains in scope
        cursor.execute("""
            CREATE TABLE "domains" (
                "domain"	TEXT NOT NULL,
                "program_url"	TEXT NOT NULL,
                "enabled"	INTEGER NOT NULL
            );
        """)

        cursor.execute("""
            CREATE TABLE "tools" (
                "name"	TEXT NOT NULL,
                "binary_path"	TEXT NOT NULL,
                "enabled"	INTEGER NOT NULL
            );
        """)

        cursor.executemany("""
                                INSERT INTO tools (name, binary_path, enabled) VALUES (?, ?, ?);
                            """,
                           (
                               ["amass", "amass", 0],
                               ["subfinder", "subfinder", 0]
                           ))

        cursor.execute("""
            CREATE TABLE "commands" (
                "id"	        INTEGER NOT NULL,
                "tool"      	TEXT    NOT NULL,
                "command"   	TEXT    NOT NULL,
                "file_command"	INTEGER NOT NULL,
                "cmd_type"   	TEXT    NOT NULL,
                PRIMARY KEY("id" AUTOINCREMENT)
            );
        """)

        cursor.executemany("""
                                INSERT INTO commands (id, tool, command, file_command, cmd_type) VALUES (?, ?, ?, ?, ?);
                            """,
                           (
                               [1, "amass", "amass enum -df $domain_file -o $output", 1, "subdomain_enum"],
                               [2, "subfinder",
                                   "subfinder -dL $domain_file -all -o $output.txt", 1, "subdomain_enum"]
                           ))

        cursor.execute(""" 
            CREATE TABLE "logs" (
                "event_name"	TEXT NOT NULL,
                "event_details"	TEXT NOT NULL,
                "timestamp"	timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.executemany("""
            INSERT INTO logs(event_name, event_details) VALUES (?, ?);
        """, [(
            "database_created", "A new database was created for this application"
        )])

        cursor.execute("""
            CREATE TABLE "schedule" (
                "id"	INTEGER NOT NULL UNIQUE,
                "hour"	INTEGER NOT NULL,
                "minute"	INTEGER NOT NULL,
                "day"	TEXT,
                "cmd_id"	INTEGER NOT NULL,
                "cmd_type"	TEXT NOT NULL
            )
        """)

        

        connection.commit()
        connection.close()

    def logEvent(self, event_info):
        """ 
        `logEvent` adds a new application event in the database.

        `event_info`: Takes the values to be inserted. E.g.[("target_added", "A new target domain.com was added")]
        """

        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()

        cursor.executemany(
            """INSERT INTO logs(event_name, event_details) VALUES (?, ?);""", event_info)

        connection.commit()
        connection.close()

    def addTargetDomain(self, domain, program_url, enabled):
        """ 
        `addTargetDomain` adds a new target domain to the database file
        """
        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()

        cursor.execute(
            f"INSERT INTO domains (domain, program_url, enabled) VALUES (\"{domain}\", \"{program_url}\", {enabled}); "
        )

        connection.commit()
        connection.close()

    def execute_select_query(self, query, parameters):
        """
        `execute_select_query` executes a SQL SELECT query and returns its output
        """

        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()
        cursor.execute(query, parameters)
        target_data = cursor.fetchall()
        connection.commit()
        connection.close()

        return target_data

    def execute_other_query(self, query, params):
        """
        `execute_other_query` executes SQL query without returning a value
        """

        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()

        cursor.execute(query, params)

        connection.commit()
        connection.close()

    def execute_multi_query(self, query, seq_of_parameters):
        """
        `execute_multi_query` runs executemany function. Takes query and parameters
        """

        connection = sqlite3.connect(self.db_file)
        cursor = connection.cursor()

        cursor.executemany(query, seq_of_parameters)

        connection.commit()
        connection.close()
