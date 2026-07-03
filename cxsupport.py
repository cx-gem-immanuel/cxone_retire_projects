from datetime import datetime, timedelta
import requests
import urllib3
import json
import time
import re
from logsupport import get_logger

logger = get_logger()


class CxSastClient:
    def __init__(self, cxsast_host, username, password, is_verbose=False, verify=True):
        self.username = username
        self.password = password
        self.cxsast_host = cxsast_host
        self.bearer_token = None
        self.is_verbose = is_verbose
        self.token_expiration = None
        self._teams_cache = {}
        self.verify = verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.debug("CxSAST client: TLS certificate verification is disabled (--insecure).")

    def get_bearer_token(self):
        if self.bearer_token is not None and datetime.now() < self.token_expiration:
            return self.bearer_token

        url = f"{self.cxsast_host}/cxrestapi/auth/identity/connect/token"

        data = {
            "username": self.username,
            "password": self.password,
            "grant_type": "password",
            "scope": "sast_rest_api access_control_api",
            "client_id": "resource_owner_client",
            "client_secret": "014DF517-39D1-4453-B7B3-9930C563627C",
        }

        response = requests.post(url, data=data, verify=self.verify)

        if response.status_code == 200:
            response_json = response.json()
            expires_in = response_json["expires_in"]
            now = datetime.now()
            self.token_expiration = now + timedelta(seconds=expires_in - 300)
            self.bearer_token = response_json["access_token"]
            return self.bearer_token

        logger.debug(f"Error: {response.status_code} - {response.text}")
        return None

    def get_projects(self):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.cxsast_host}/cxrestapi/projects"
        headers = {
            "Accept": "application/json;v=5.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            return response.json()

        logger.debug(f"Error: {response.status_code} - {response.text}")
        return None

    def get_teams_dict(self):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.cxsast_host}/cxrestapi/auth/teams"
        headers = {
            "Accept": "application/json;v=5.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            teams_dict = {}
            for team in response.json():
                teams_dict[team["id"]] = team["fullName"]
            return teams_dict

        logger.debug(f"Error: {response.status_code} - {response.text}")
        return None

    def get_team_id(self, team_name):
        team_id = self._teams_cache.get(team_name, None)
        if team_id is not None:
            return team_id

        teams = self.get_teams_dict()
        for team in teams.get("teams", []):
            if team["fullname"] == team_name:
                team_id = team["id"]
                self._teams_cache[team_name] = team_id
                break
        return team_id

    def get_ldap_groups_dict(self):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.cxsast_host}/cxrestapi/auth/ldapteammappings"
        headers = {
            "Accept": "application/json;v=5.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        ldap_groups_dict = {}

        if response.status_code == 200:
            def cn(dn):
                match = re.match(r"CN=([^,]+)", dn, re.IGNORECASE)
                return match.group(1) if match else None

            for ldap_group in response.json():
                dn = ldap_group["ldapGroupDn"]
                cxone_group = cn(dn)
                ldap_groups_dict[ldap_group["teamId"]] = cxone_group
            return ldap_groups_dict

        logger.debug(f"Error: {response.status_code} - {response.text}")
        return ldap_groups_dict


class CxOneClient:
    def __init__(self, iam_host, ast_host, tenant, api_key, is_verbose=False, verify=True):
        self.api_key = api_key
        self.iam_host = iam_host
        self.ast_host = ast_host
        self.tenant = tenant
        self.bearer_token = None
        self.is_verbose = is_verbose
        self.token_expiration = None
        self._applications_cache = {}
        self._groups_cache = {}
        self.verify = verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.debug("CxOne client: TLS certificate verification is disabled (--insecure).")

    def get_bearer_token(self):
        if self.bearer_token is not None and datetime.now() < self.token_expiration:
            return self.bearer_token

        url = f"{self.iam_host}/auth/realms/{self.tenant}/protocol/openid-connect/token"
        data = {
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": f"{self.api_key}",
        }

        response = requests.post(url, data=data, verify=self.verify)
        if response.status_code == 200:
            response_json = response.json()
            expires_in = response_json["expires_in"]
            now = datetime.now()
            self.token_expiration = now + timedelta(seconds=expires_in - 300)
            self.bearer_token = response_json["access_token"]
            return self.bearer_token

        logger.debug(f"Error: {response.status_code} - {response.text}")
        return None

    def get_groups_dict(self):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.iam_host}/auth/admin/realms/{self.tenant}/groups"
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        groups_dict = {}
        if response.status_code == 200:
            groups = response.json()
            for group in groups:
                groups_dict[group["name"]] = group["id"]
        else:
            logger.debug(f"Error: {response.status_code} - {response.text}")

        return groups_dict

    def get_projects_dict(self):
        self.bearer_token = self.get_bearer_token()
        limit = 100
        offset = 0
        remaining = limit

        projects = []
        projects_dict = {}
        nProjectsInOrg = -1

        while remaining > 0:
            url = f"{self.ast_host}/api/projects?limit={limit}&offset={offset}"
            headers = {
                "Accept": "application/json; version=1.0",
                "Authorization": f"Bearer {self.bearer_token}",
            }

            response = requests.get(url, headers=headers, verify=self.verify)
            if response.status_code == 200:
                jsonResp = response.json()
                nProjectsInOrg = (
                    nProjectsInOrg
                    if nProjectsInOrg != -1
                    else jsonResp["filteredTotalCount"]
                )
                projectsJson = jsonResp["projects"]
                if projectsJson:
                    projects.extend(projectsJson)
                    for p in projectsJson:
                        projects_dict[p["name"]] = p["id"]
                    remaining = nProjectsInOrg - len(projects)
                    offset += limit
                else:
                    break
            else:
                logger.debug(
                    f"Could not fetch projects. Reason: {response.reason}"
                )
                break

        return projects_dict

    def create_application(
        self, application_name, description=None, criticality=3, rules=None, tags=None
    ):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/applications"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json; version=1.0",
        }

        data = {
            "name": application_name,
            "description": description,
            "criticality": criticality,
            "rules": rules if rules else [],
            "tags": tags if tags else {},
        }

        response = requests.post(url, headers=headers, data=json.dumps(data), verify=self.verify)
        if response.status_code == 201:
            jsonResp = response.json()
            application_id = jsonResp["id"]
            return application_id

        logger.debug(
            f"Error creating application {application_name}: "
            f"{response.status_code} - {response.text}"
        )
        return None

    def is_authorized(self, application_id, group_id):
        self.bearer_token = self.get_bearer_token()
        url = (
            f"{self.ast_host}/api/access-management"
            f"?entity-id={group_id}&resource-id={application_id}"
        )
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        rc = -1
        if response.status_code == 200:
            rc = 1
        elif response.status_code == 404:
            rc = 0
        return rc

    def authorize_application(self, application_id, group_id):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/access-management"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json; version=1.0",
        }

        data = {
            "entityID": group_id,
            "entityType": "group",
            "resourceType": "application",
            "resourceID": application_id,
        }

        response = requests.post(url, headers=headers, data=json.dumps(data), verify=self.verify)
        rc = 0
        if response.status_code != 201:
            rc = 1
            logger.debug(
                f"Authorization Error Code: {response.status_code}, "
                f"Message: {response.text}"
            )
        return rc

    def get_group_id(self, group_name):
        group_id = self._groups_cache.get(group_name, None)
        if group_id is not None:
            return group_id

        groups = self.get_groups()
        for group in groups.get("groups", []):
            if group["name"] == group_name:
                group_id = group["id"]
                self._groups_cache[group_name] = group_id
                logger.debug(
                    f"Group ID for group [{group_name}]: {group_id}"
                )
                break
        return group_id

    def get_application_id(self, application_name):
        application_id = self._applications_cache.get(application_name, None)
        if application_id is not None:
            return application_id

        applications = self.get_applications_dict()
        for app in applications.get("applications", []):
            if app["name"] == application_name:
                application_id = app["id"]
                self._applications_cache[application_name] = application_id
                logger.debug(
                    f"Application ID for name [{application_name}]: "
                    f"{application_id}"
                )
                break
        return application_id

    def get_applications_dict(self):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/applications/"
        headers = {
            "accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        applications_dict = {}
        if response.status_code == 200:
            for app in response.json()["applications"]:
                applications_dict[app["name"]] = app["id"]
        else:
            logger.debug(
                f"Error retrieving applications: {response.status_code} - "
                f"{response.text}"
            )

        return applications_dict

    def get_groups(self, group_name=None):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.iam_host}/auth/admin/realms/{self.tenant}/groups"
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            groups = response.json()
            if group_name:
                groups = [g for g in groups if g["name"] == group_name]
            return groups

        logger.debug(f"Error: {response.status_code} - {response.text}")
        return None

    def update_project_tags(self, project_id, tags_list):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/projects/{project_id}"
        headers = {
            "accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json; version=1.0",
        }

        data = {
            "tags": {tag: "" for tag in tags_list},
        }

        logger.debug(
            f"Updating project [id:{project_id}] with tags: {data['tags']}"
        )

        response = requests.patch(url, headers=headers, data=json.dumps(data), verify=self.verify)
        if response.status_code == 204:
            logger.debug(
                f"Successfully updated tags for project {project_id}"
            )
            return True

        logger.debug(
            f"Error updating tags for project {project_id}: "
            f"{response.status_code} - {response.text}"
        )
        return False

    def get_projects_page(self, offset: int, limit: int = 100):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/projects?limit={limit}&offset={offset}"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            body = response.json()
            total = body.get("filteredTotalCount", 0)
            page_dict = {
                p["name"]: p["id"] for p in (body.get("projects") or [])
            }
            return page_dict, total

        logger.debug(
            f"Could not fetch projects page (offset={offset}): "
            f"{response.reason}"
        )
        return {}, 0

    def get_applications_page(self, offset: int, limit: int = 100):
        self.bearer_token = self.get_bearer_token()
        url = (
            f"{self.ast_host}/api/applications/?limit={limit}&offset={offset}"
        )
        headers = {
            "accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            body = response.json()
            total = body.get("filteredTotalCount") or body.get(
                "totalCount", 0
            )
            page_dict = {
                a["name"]: a["id"] for a in (body.get("applications") or [])
            }
            return page_dict, total

        logger.debug(
            f"Could not fetch applications page (offset={offset}): "
            f"{response.reason}"
        )
        return {}, 0

    def delete_project(self, project_id):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/projects/{project_id}"
        headers = {
            "accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.delete(url, headers=headers, verify=self.verify)
        if response.status_code == 204:
            logger.debug(f"Successfully deleted project {project_id}")
            return True

        logger.debug(
            f"Error deleting project {project_id}: {response.status_code} - "
            f"{response.text}"
        )
        return False

    def delete_application(self, application_id):
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/applications/{application_id}"
        headers = {
            "accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.delete(url, headers=headers, verify=self.verify)
        if response.status_code == 204:
            logger.debug(
                f"Successfully deleted application {application_id}"
            )
            return True

        logger.debug(
            f"Error deleting application {application_id}: "
            f"{response.status_code} - {response.text}"
        )
        return False

    def create_group(self, group_name):
        url = f"{self.iam_host}/auth/admin/realms/{self.tenant}/groups"
        headers = {
            "Authorization": f"Bearer {self.get_bearer_token()}",
            "Content-Type": "application/json",
        }

        data = {
            "name": group_name,
        }

        response = requests.post(url, headers=headers, json=data, verify=self.verify)
        if response.status_code == 201:
            return True

        logger.debug(
            f"Error: {response.status_code} - {response.text}"
        )
        return False

    def delete_roles_in_group(self, group_id, client_id):
        url = (
            f"{self.iam_host}/auth/admin/realms/{self.tenant}/groups/"
            f"{group_id}/role-mappings/clients/{client_id}"
        )
        headers = {
            "Authorization": f"Bearer {self.get_bearer_token()}",
            "Content-Type": "application/json",
        }

        response = requests.delete(url, headers=headers, verify=self.verify)
        if response.status_code == 204:
            return True

        logger.debug(
            f"Error: {response.status_code} - {response.text}"
        )
        return False

    def assign_roles_to_group(self, group_id, client_id, roles):
        url = (
            f"{self.iam_host}/auth/admin/realms/{self.tenant}/groups/"
            f"{group_id}/role-mappings/clients/{client_id}"
        )
        headers = {
            "Authorization": f"Bearer {self.get_bearer_token()}",
            "Content-Type": "application/json",
        }

        data = []
        for role in roles:
            data.append(
                {
                    "id": role["id"],
                    "name": role["name"],
                }
            )

        response = requests.post(url, headers=headers, json=data, verify=self.verify)
        if response.status_code == 204:
            return True

        logger.debug(
            f"Error: {response.status_code} - {response.text}"
        )
        return False

    def get_roles(self, client_id):
        url = (
            f"{self.iam_host}/auth/admin/realms/{self.tenant}/clients/"
            f"{client_id}/roles"
        )
        headers = {
            "Authorization": f"Bearer {self.get_bearer_token()}",
            "Content-Type": "application/json",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            return response.json()

        logger.debug(
            f"Error: {response.status_code} - {response.text}"
        )
        return None

    def get_role_id(self, client_id, role_name):
        roles = self.get_roles(client_id)
        if not roles:
            return None

        for role in roles:
            if role["name"] == role_name:
                return role["id"]
        return None

    def get_client_id(self, client_name):
        clients = self.get_clients()
        if not clients:
            return None

        for client in clients:
            if client["clientId"] == client_name:
                return client["id"]
        return None

    def get_clients(self):
        url = f"{self.iam_host}/auth/admin/realms/{self.tenant}/clients"
        headers = {
            "Authorization": f"Bearer {self.get_bearer_token()}",
            "Content-Type": "application/json",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            return response.json()

        logger.debug(
            f"Error: {response.status_code} - {response.text}"
        )
        return None

    # ===================== CxAudit / Query Editor (read-only) =====================

    def start_audit_session(self, language: str | None) -> dict | None:
        """
        Create a new Query Editor (CxAudit) session.  If language is provided
        the session is scoped to that language; if None, no filter is sent and
        all languages are returned.
        """
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/query-editor/sessions"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json",
        }

        body = {"scanner": "sast"}
        if language:
            body["filter"] = language

        logger.debug(f"Starting Audit session with body: {body}")

        response = requests.post(url, headers=headers, data=json.dumps(body), verify=self.verify)
        if response.status_code != 200:
            logger.debug(
                f"Error creating Audit session for language [{language}]: "
                f"{response.status_code} - {response.text}"
            )
            return None

        return response.json()

    def get_audit_session_status(self, session_id: str, request_id: str) -> dict | None:
        """
        Retrieve the status of a Query Editor (CxAudit) session request.

        Uses:
            GET /api/query-editor/sessions/{session_id}/requests/{request_id}
        """
        self.bearer_token = self.get_bearer_token()
        url = (
            f"{self.ast_host}/api/query-editor/sessions/"
            f"{session_id}/requests/{request_id}"
        )
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            return response.json()

        logger.debug(
            f"Error retrieving Audit session status for [{session_id}], "
            f"request [{request_id}]: {response.status_code} - {response.text}"
        )
        return None

    def keep_alive_audit_session(self, session_id: str) -> bool:
        """
        Send a keep-alive to an existing Audit session.

        Uses:
            PATCH /api/query-editor/sessions/{session_id}
        """
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/query-editor/sessions/{session_id}"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.patch(url, headers=headers, verify=self.verify)
        if response.status_code in (200, 204):
            return True

        logger.debug(
            f"Keep-alive failed for Audit session [{session_id}]: "
            f"{response.status_code} - {response.text}"
        )
        return False

    def wait_for_audit_session_ready(
        self,
        session: dict,
        max_wait_seconds: int = 1800,
        poll_interval_seconds: int = 10,
    ) -> list[str] | None:
        """
        Poll the Audit session until it is loaded or fails.

        This is read-only: it only checks status and keeps the session alive.

        Returns:
            The 'value' list from the success response (usually languages list),
            or None on failure or timeout.
        """
        session_id = session.get("id")
        data = session.get("data") or {}
        request_id = data.get("requestID")

        if not session_id or not request_id:
            logger.debug(
                f"Cannot wait for Audit session; missing id or requestID in {session}"
            )
            return None

        elapsed = 0
        polls = 0
        while elapsed < max_wait_seconds:
            time.sleep(poll_interval_seconds)
            elapsed += poll_interval_seconds
            polls += 1

            if polls % 10 == 0:
                self.keep_alive_audit_session(session_id)

            status_body = self.get_audit_session_status(session_id, request_id)
            if not status_body:
                continue

            if status_body.get("completed") is True:
                status = status_body.get("status")
                value = status_body.get("value")
                if status == "Finished":
                    return value
                if status == "Failed":
                    return None

                return value

        return None

    def delete_audit_session(self, session_id: str) -> bool:
        """
        Delete (end) an existing Audit session.

        Uses:
            DELETE /api/query-editor/sessions/{session_id}
        """
        if not session_id:
            return False

        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/query-editor/sessions/{session_id}"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.delete(url, headers=headers, verify=self.verify)
        if response.status_code in (200, 204):
            return True

        logger.debug(
            f"Error deleting Audit session [{session_id}]: "
            f"{response.status_code} - {response.text}"
        )
        return False

    def get_query_tree(self, session_id: str) -> list[dict] | None:
        """
        Retrieve the full query tree for an Audit session.

        Uses:
            GET /api/query-editor/sessions/{session_id}/queries
        """
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/query-editor/sessions/{session_id}/queries"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        response = requests.get(url, headers=headers, verify=self.verify)
        if response.status_code == 200:
            return response.json() or []

        logger.debug(
            f"Error retrieving query tree for session [{session_id}]: "
            f"{response.status_code} - {response.text}"
        )
        return None

    def flatten_query_tree(
        self,
        tree: list[dict],
        language: str | None = None,
        level: str | None = None,
    ) -> list[dict]:
        """
        Flatten the query tree into a list of query records, optionally filtering
        by language and level ('tenant', 'application', 'project').

        Each returned dict contains:
            id        : query id (tree 'key')
            name      : query name (tree 'title')
            language  : root language title
            level     : 'Tenant' / 'Application' / 'Project'
            category  : category title
        """
        if not tree:
            return []

        wanted_language = language.lower() if language else None
        wanted_level = level.lower() if level else None

        queries: list[dict] = []

        for lang_node in tree:
            lang_title = lang_node.get("title") or ""
            lang_key = lang_node.get("key") or ""
            lang_name_lower = lang_title.lower()

            if wanted_language and lang_name_lower != wanted_language:
                continue

            children = lang_node.get("children") or []
            for group_node in children:
                group_title = group_node.get("title") or ""
                group_key = group_node.get("key") or ""
                group_title_lower = group_title.lower()

                if group_title not in ("Tenant", "Application", "Project"):
                    continue

                if wanted_level and group_title_lower != wanted_level:
                    continue

                categories = group_node.get("children") or []
                for category_node in categories:
                    category_title = category_node.get("title") or ""
                    category_key = category_node.get("key") or ""
                    query_nodes = category_node.get("children") or []

                    for q_node in query_nodes:
                        q_id = q_node.get("key")
                        q_name = q_node.get("title") or ""
                        if not q_id:
                            continue

                        record = {
                            "id": q_id,
                            "name": q_name,
                            "language": lang_title,
                            "level": group_title,
                            "category": category_title,
                        }
                        queries.append(record)

        return queries

    def get_query_overrides(
        self,
        language: str | None,
        level: str | None,
        session_id: str,
    ) -> list[dict]:
        """
        Retrieve a flattened list of queries for the given language and level
        within an Audit session, using client-side filtering.

        This is a read-only operation.
        """
        tree = self.get_query_tree(session_id)
        if tree is None:
            return []

        normalized_level = None
        if level:
            lvl = level.lower()
            if lvl in ("tenant", "application", "project"):
                normalized_level = lvl

        queries = self.flatten_query_tree(
            tree=tree,
            language=language,
            level=normalized_level,
        )

        return queries

    def get_query_details(
        self,
        query_id: str,
        session_id: str | None = None,
        include_source: bool = True,
    ) -> dict | None:
        """
        Retrieve metadata (and optionally source code) for a specific query.

        Uses:
            GET /api/query-editor/sessions/{session_id}/queries/{query_id}
        when session_id is provided, or /api/query-editor/queries/{query_id}
        otherwise.
        """
        if session_id:
            url = (
                f"{self.ast_host}/api/query-editor/sessions/{session_id}"
                f"/queries/{query_id}"
            )
        else:
            url = f"{self.ast_host}/api/query-editor/queries/{query_id}"

        params = {}
        if include_source:
            params["includeSource"] = "true"

        response = self._get(url, params=params or None)
        if response.status_code == 200:
            return response.json()

        logger.debug(
            f"Error retrieving query [{query_id}] details: "
            f"{response.status_code} - {response.text}"
        )
        return None

    def create_query_override(
        self,
        session_id: str,
        query_name: str,
        language: str,
        group: str,
        severity: int,
        executable: bool,
        cwe: int,
        description: str,
        source: str,
        level: str = "Application",
        application_id: str | None = None,
        project_id: str | None = None,
        poll_attempts: int = 10,
        poll_interval: int = 10,
        source_poll_attempts: int = 30,
        source_poll_interval: int = 10,
    ) -> str | None:
        """
        Create or overwrite a query override in CxOne at the specified level
        (Tenant / Application / Project) within an active Audit session.

        The operation is two-phase:
          1. POST the query metadata to register the override and obtain its ID.
          2. PUT the source code against that ID.

        Both phases are async on the server side; each is polled until
        ``completed == true``.  A secondary source-verification read is
        performed after the PUT to guard against a known race condition
        (AST-108988) where the source may not persist on the first attempt.

        Parameters
        ----------
        session_id : str
            Active Query Editor (Audit) session ID.
        query_name : str
            Name of the query to create or override.
        language : str
            CxOne language name, e.g. ``"CSharp"``, ``"Java"``.
        group : str
            Query group / category name within the language.
        severity : int
            Numeric severity: 0=Info, 1=Low, 2=Medium, 3=High, 4=Critical.
        executable : bool
            Whether the query is executable.
        cwe : int
            CWE identifier (0 if not applicable).
        description : str
            Description ID for the query.
        source : str
            CxQL source code.
        level : str
            Override level: ``"Tenant"``, ``"Application"``, or ``"Project"``.
            Defaults to ``"Application"``.
        application_id : str | None
            Required when *level* is ``"Application"``.
        project_id : str | None
            Required when *level* is ``"Project"``.
        poll_attempts : int
            Maximum polling iterations when waiting for the metadata POST to complete.
        poll_interval : int
            Seconds to wait between metadata polling attempts.
        source_poll_attempts : int
            Maximum polling iterations when waiting for the source PUT to complete.
        source_poll_interval : int
            Seconds to wait between source polling attempts.

        Returns
        -------
        str | None
            The CxOne query ID of the created/updated override, or ``None`` on
            failure.

        Raises
        ------
        ValueError
            If the metadata POST or source PUT phase fails definitively.
        """
        _SEVERITY_MAP = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        severity_str = _SEVERITY_MAP.get(severity, "Low")

        # ------------------------------------------------------------------
        # Phase 1 - register the query override (metadata POST)
        # ------------------------------------------------------------------
        override_params: dict = {
            "name":        query_name,
            "language":    language,
            "group":       group,
            "severity":    severity_str,
            "executable":  executable,
            "presets":     [],
            "cwe":         cwe,
            "description": description,
            "level":       level,
        }

        self.bearer_token = self.get_bearer_token()
        post_url = f"{self.ast_host}/api/query-editor/sessions/{session_id}/queries"
        headers = {
            "Accept":        "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type":  "application/json",
        }

        # Log all of the values in the override_params dict
        logger.debug(
            f"Creating query override with parameters: "
            f"name={query_name}, language={language}, group={group}, "
            f"severity={severity_str}, executable={executable}, cwe={cwe}, "
            f"description={description}, level={level}"
        )

        post_resp = requests.post(post_url, headers=headers, json=override_params, verify=self.verify)
        if post_resp.status_code not in (200, 201, 202):
            logger.debug(
                f"create_query_override POST failed [{post_resp.status_code}]: "
                f"{post_resp.text}"
            )
            raise ValueError(
                f"Failed to create query override '{query_name}': "
                f"HTTP {post_resp.status_code}"
            )

        post_body = post_resp.json()
        request_id = post_body.get("id")
        if not request_id:
            logger.debug(f"create_query_override: unexpected POST response: {post_body}")
            raise ValueError(
                f"Failed to create query override '{query_name}': no request id in response"
            )

        # Poll for the async metadata operation to complete
        status_url = (
            f"{self.ast_host}/api/query-editor/sessions/{session_id}"
            f"/requests/{request_id}"
        )
        query_id: str | None = None
        for attempt in range(poll_attempts):
            time.sleep(poll_interval)
            self.bearer_token = self.get_bearer_token()
            headers["Authorization"] = f"Bearer {self.bearer_token}"
            status_resp = requests.get(status_url, headers=headers, verify=self.verify)
            if status_resp.status_code != 200:
                logger.debug(
                    f"create_query_override: status poll failed "
                    f"[{status_resp.status_code}] attempt {attempt + 1}"
                )
                continue
            status = status_resp.json()
            if status.get("completed"):
                if status.get("status") == "Failed":
                    logger.debug(f"create_query_override: metadata phase Failed: {status}")
                    raise ValueError(
                        f"Failed to save query override '{query_name}': {status}"
                    )
                value = status.get("value") or {}
                query_id = value.get("id")
                logger.debug(
                    f"create_query_override: metadata phase complete, "
                    f"query_id={query_id!r}"
                )
                break

        if not query_id:
            raise ValueError(
                f"Failed to save query override '{query_name}': "
                f"timed out waiting for metadata phase to complete"
            )

        # ------------------------------------------------------------------
        # Phase 2 - save the source code (PUT)
        # ------------------------------------------------------------------
        source_url = (
            f"{self.ast_host}/api/query-editor/sessions/{session_id}/queries/source"
        )
        query_source = [{"id": query_id, "source": source}]

        self.bearer_token = self.get_bearer_token()
        headers["Authorization"] = f"Bearer {self.bearer_token}"
        put_resp = requests.put(source_url, headers=headers, json=query_source, verify=self.verify)
        if put_resp.status_code not in (200, 201, 202):
            logger.debug(
                f"create_query_override source PUT failed [{put_resp.status_code}]: "
                f"{put_resp.text}"
            )
            raise ValueError(
                f"Failed to save source for query override '{query_name}': "
                f"HTTP {put_resp.status_code}"
            )

        put_body = put_resp.json()
        save_request_id = put_body.get("id")
        if not save_request_id:
            logger.debug(f"create_query_override: unexpected PUT response: {put_body}")
            raise ValueError(
                f"Failed to save source for query override '{query_name}': "
                f"no request id in PUT response"
            )

        # Poll for the async source-save operation to complete, with
        # source-verification retry to guard against AST-108988.
        save_status_url = (
            f"{self.ast_host}/api/query-editor/sessions/{session_id}"
            f"/requests/{save_request_id}"
        )
        source_saved = False
        for attempt in range(source_poll_attempts):
            time.sleep(source_poll_interval)
            self.bearer_token = self.get_bearer_token()
            headers["Authorization"] = f"Bearer {self.bearer_token}"
            save_status_resp = requests.get(save_status_url, headers=headers, verify=self.verify)
            if save_status_resp.status_code != 200:
                logger.debug(
                    f"create_query_override: source status poll failed "
                    f"[{save_status_resp.status_code}] attempt {attempt + 1}"
                )
                continue

            save_status = save_status_resp.json()
            if not save_status.get("completed"):
                continue

            save_value = save_status.get("value") or {}
            saved_query_id = save_value.get("id")
            if not saved_query_id:
                logger.debug(
                    f"create_query_override: source save completed but no id "
                    f"in value: {save_status}"
                )
                break

            # Verify the source actually persisted (workaround for AST-108988)
            verify_url = (
                f"{self.ast_host}/api/query-editor/sessions/{session_id}"
                f"/queries/{saved_query_id}?includeMetadata=false"
            )
            verify_resp = requests.get(verify_url, headers=headers, verify=self.verify)
            if verify_resp.status_code == 200:
                saved_source = verify_resp.json().get("source") or ""
                if source and saved_source[:10] != source[:10]:
                    # Source didn't persist - retry the PUT
                    logger.debug(
                        f"create_query_override: source mismatch on attempt "
                        f"{attempt + 1}, retrying PUT"
                    )
                    self.bearer_token = self.get_bearer_token()
                    headers["Authorization"] = f"Bearer {self.bearer_token}"
                    put_resp = requests.put(source_url, headers=headers, json=query_source, verify=self.verify)
                    put_body = put_resp.json()
                    new_save_id = put_body.get("id")
                    if new_save_id:
                        save_status_url = (
                            f"{self.ast_host}/api/query-editor/sessions/{session_id}"
                            f"/requests/{new_save_id}"
                        )
                    continue

            source_saved = True
            logger.debug(
                f"create_query_override: source saved, query_id={saved_query_id!r}"
            )
            break

        if not source_saved:
            logger.debug(
                f"create_query_override: source save timed out for '{query_name}'"
            )
            raise ValueError(
                f"Failed to verify saved source for query override '{query_name}'"
            )

        return query_id

    @staticmethod
    def query_has_custom_logic(query_data: dict | None) -> bool:
        """
        Heuristic: a query has NO custom logic if its entire meaningful body
        reduces to a single base.xxx(...) call in one of these forms:

            base.Foo();                        # bare call
            return base.Foo();                 # returned
            result = base.Foo();               # assigned to any variable
            result.Add(base.Foo());            # passed as sole arg to result.Add

        Anything with more than one non-empty, non-comment statement, or any
        statement that doesn't match the above forms, is considered custom logic.
        """
        if not query_data:
            return False

        source = (
            query_data.get("source")
            or query_data.get("code")
            or query_data.get("body")
            or ""
        )

        if not isinstance(source, str):
            return False

        # Strip comments (// …) and blank lines; collect remaining statements
        statements = []
        for raw_line in source.splitlines():
            line = re.sub(r'//.*$', '', raw_line).strip().rstrip(';').strip()
            if line:
                statements.append(line)

        if not statements:
            return False

        # More than one statement -> definitely custom logic
        if len(statements) > 1:
            return True

        stmt = statements[0]

        # Bare call:           base.Foo(...)
        # Returned call:       return base.Foo(...)
        # Assigned call:       <var> = base.Foo(...)
        # result.Add wrapper:  result.Add(base.Foo(...))
        no_custom_patterns = [
            r"^base\.[A-Za-z0-9_]+\s*\(.*\)$",
            r"^return\s+base\.[A-Za-z0-9_]+\s*\(.*\)$",
            r"^[A-Za-z0-9_]+\s*=\s*base\.[A-Za-z0-9_]+\s*\(.*\)$",
            r"^[A-Za-z0-9_]+\.Add\s*\(\s*base\.[A-Za-z0-9_]+\s*\(.*\)\s*\)$",
        ]

        for pattern in no_custom_patterns:
            if re.match(pattern, stmt, flags=re.IGNORECASE | re.DOTALL):
                return False

        return True

    # ------------------------------------------------------------------
    # Preset / configuration helpers
    # ------------------------------------------------------------------

    def get_all_projects_id_map(self) -> dict:
        """
        Return {project_id: project_object} for every project in the tenant,
        fetching all pages automatically.  Each value is the full project dict
        from the API, which includes 'name', 'applicationIds', tags, etc.
        """
        limit = 100
        offset = 0
        total = None
        id_to_project: dict = {}

        while True:
            self.bearer_token = self.get_bearer_token()
            url = f"{self.ast_host}/api/projects?limit={limit}&offset={offset}"
            headers = {
                "Accept": "application/json; version=1.0",
                "Authorization": f"Bearer {self.bearer_token}",
            }

            response = requests.get(url, headers=headers, verify=self.verify)
            if response.status_code != 200:
                logger.debug(
                    f"Could not fetch projects (offset={offset}): {response.reason}"
                )
                break

            body = response.json()
            if total is None:
                total = body.get("filteredTotalCount", 0)

            page = body.get("projects") or []
            if not page:
                break

            for p in page:
                id_to_project[p["id"]] = p

            offset += len(page)
            if offset >= total:
                break

        return id_to_project

    def get_all_applications_id_map(self) -> dict:
        """
        Return {application_id: application_name} for every application in the
        tenant, fetching all pages automatically.
        """
        limit = 100
        offset = 0
        total = None
        id_to_name: dict = {}

        while True:
            self.bearer_token = self.get_bearer_token()
            url = f"{self.ast_host}/api/applications/?limit={limit}&offset={offset}"
            headers = {
                "Accept": "application/json; version=1.0",
                "Authorization": f"Bearer {self.bearer_token}",
            }

            response = requests.get(url, headers=headers, verify=self.verify)
            if response.status_code != 200:
                logger.debug(
                    f"Could not fetch applications (offset={offset}): {response.reason}"
                )
                break

            body = response.json()
            if total is None:
                total = body.get("filteredTotalCount") or body.get("totalCount", 0)

            page = body.get("applications") or []
            if not page:
                break

            for a in page:
                id_to_name[a["id"]] = a["name"]

            offset += len(page)
            if offset >= total:
                break

        return id_to_name

    def _get(self, url: str, params: dict | None = None,
             retries: int = 4, backoff: float = 2.0):
        """
        GET wrapper with exponential backoff retry.

        Retries on connection errors (RemoteDisconnected, etc.) and on
        HTTP 429 / 5xx responses.  Waits backoff * 2^attempt seconds between
        attempts (2 s, 4 s, 8 s, 16 s by default).
        """
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.get_bearer_token()}",
        }
        for attempt in range(retries + 1):
            try:
                response = requests.get(url, headers=headers, params=params, verify=self.verify)
                if response.status_code in (429, 500, 502, 503, 504, 529) and attempt < retries:
                    wait = backoff * (2 ** attempt)
                    logger.debug(
                        f"HTTP {response.status_code} on {url} – "
                        f"retrying in {wait:.0f}s (attempt {attempt + 1}/{retries})"
                    )
                    time.sleep(wait)
                    continue
                if attempt > 0:
                    logger.debug(f"Retry succeeded on {url} (attempt {attempt + 1})")
                return response
            except requests.exceptions.ConnectionError as exc:
                if attempt < retries:
                    wait = backoff * (2 ** attempt)
                    logger.debug(
                        f"Connection error on {url}: {exc} – "
                        f"retrying in {wait:.0f}s (attempt {attempt + 1}/{retries})"
                    )
                    time.sleep(wait)
                else:
                    raise

    def get_project_configuration(self, project_id: str) -> list:
        """
        Return the configuration item list for a project.

        Uses:
            GET /api/configuration/project?project-id=<project_id>
        """
        url = f"{self.ast_host}/api/configuration/project"
        response = self._get(url, params={"project-id": project_id})
        if response.status_code == 200:
            return response.json() or []

        logger.debug(
            f"Error fetching project config for [{project_id}]: "
            f"{response.status_code} - {response.text}"
        )
        return []

    def get_project_last_scan(self, project_id: str) -> dict | None:
        """
        Return the last-scan record for a project on its main branch, or None.

        Uses:
            GET /api/projects/last-scan?project-ids=<project_id>&use-main-branch=true
        """
        url = f"{self.ast_host}/api/projects/last-scan"
        params = {
            "offset": 0,
            "limit": 1,
            "project-ids": project_id,
            "use-main-branch": "true",
        }
        response = self._get(url, params=params)
        if response.status_code == 200:
            return (response.json() or {}).get(project_id)

        logger.debug(
            f"Error fetching last scan for project [{project_id}]: "
            f"{response.status_code} - {response.text}"
        )
        return None

    def get_scan_configuration(self, project_id: str, scan_id: str) -> list:
        """
        Return the configuration item list for a specific scan.

        Uses:
            GET /api/configuration/scan?project-id=<project_id>&scan-id=<scan_id>
        """
        url = f"{self.ast_host}/api/configuration/scan"
        response = self._get(url, params={"project-id": project_id, "scan-id": scan_id})
        if response.status_code == 200:
            return response.json() or []

        logger.debug(
            f"Error fetching scan config for project [{project_id}] / "
            f"scan [{scan_id}]: {response.status_code} - {response.text}"
        )
        return []

    @staticmethod
    def extract_sast_preset(config_items: list) -> str:
        """
        Return the SAST preset name from a configuration item list,
        or an empty string if not present.
        """
        for item in config_items:
            if item.get("name") == "presetName" and item.get("category") == "sast":
                return item.get("value") or ""
        return ""

    # ------------------------------------------------------------------
    # Report lifecycle: look up project → latest scan → create → poll → download
    # ------------------------------------------------------------------

    def get_project_id(self, project_name: str) -> str | None:
        """
        Resolve a single project name to its UUID.
        Convenience wrapper around get_project_ids_for_batch().
        """
        result = self.get_project_ids_for_batch([project_name])
        return result.get(project_name)

    # Maximum safe URL length before splitting into sub-batches.
    # Most servers/proxies accept 2 KB; we stay well under that.
    _MAX_REGEX_URL_LEN = 1800
    # Retry policy for transient network errors
    _BATCH_RETRIES     = 3
    _BATCH_RETRY_DELAY = 5   # seconds between retries

    def get_project_ids_for_batch(self, project_names: list[str]) -> dict[str, str]:
        """
        Resolve a list of project names to their UUIDs using the
        ``name-regex`` filter parameter.

        The regex is built as an exact-match alternation::

            ^(name-one|name-two|name-three)$

        If the resulting URL would exceed _MAX_REGEX_URL_LEN characters the
        list is automatically split into smaller sub-batches and the results
        are merged, so callers always get a single combined dict back.

        Transient network errors (ConnectionError, Timeout, RemoteDisconnected)
        are retried up to _BATCH_RETRIES times with a fixed delay before the
        sub-batch is abandoned and an empty result is returned for those names.

        Parameters
        ----------
        project_names : List of project names to resolve.

        Returns
        -------
        dict mapping project_name -> project_id for every name that was found.
        Missing names are simply absent from the result.
        """
        if not project_names:
            return {}

        # ── Delegate to internal method that handles splitting + retries ──
        result: dict[str, str] = {}
        self._resolve_sub_batch(project_names, result)
        return result

    def _resolve_sub_batch(self, project_names: list[str],
                           result: dict[str, str]) -> None:
        """
        Attempt to resolve *project_names* in one API call.  If the URL would
        be too long the list is halved recursively until each chunk fits.
        Retries are applied at the leaf level (single API call).
        """
        if not project_names:
            return

        self.bearer_token = self.get_bearer_token()

        alternation = "|".join(re.escape(n) for n in project_names)
        name_regex  = f"^({alternation})$"
        encoded     = requests.utils.quote(name_regex, safe="")
        url = (
            f"{self.ast_host}/api/projects"
            f"?name-regex={encoded}"
            f"&limit={len(project_names) + 10}"
        )

        # Split if URL is too long
        if len(url) > self._MAX_REGEX_URL_LEN and len(project_names) > 1:
            mid = len(project_names) // 2
            logger.debug(
                f"name-regex URL too long ({len(url)} chars); "
                f"splitting {len(project_names)} names into two sub-batches."
            )
            self._resolve_sub_batch(project_names[:mid], result)
            self._resolve_sub_batch(project_names[mid:], result)
            return

        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
        }

        logger.debug(
            f"Resolving {len(project_names)} project name(s) via name-regex"
        )

        for attempt in range(1, self._BATCH_RETRIES + 1):
            try:
                response = requests.get(
                    url, headers=headers, verify=self.verify, timeout=30
                )
                if response.status_code != 200:
                    logger.debug(
                        f"get_project_ids_for_batch: HTTP {response.status_code} "
                        f"(attempt {attempt}) – {response.text}"
                    )
                    # Non-transient HTTP error — don't retry
                    return

                name_set = set(project_names)
                for project in (response.json().get("projects") or []):
                    name = project.get("name")
                    pid  = project.get("id")
                    if name in name_set and pid:
                        result[name] = pid
                        logger.debug(f"  '{name}' -> {pid}")

                missing = name_set - result.keys()
                if missing:
                    logger.debug(
                        f"  {len(missing)} project(s) not found: "
                        + ", ".join(sorted(missing))
                    )
                return   # success

            except requests.exceptions.ConnectionError as exc:
                logger.debug(
                    f"get_project_ids_for_batch: connection error on attempt "
                    f"{attempt}/{self._BATCH_RETRIES} – {exc}"
                )
            except requests.exceptions.Timeout as exc:
                logger.debug(
                    f"get_project_ids_for_batch: timeout on attempt "
                    f"{attempt}/{self._BATCH_RETRIES} – {exc}"
                )

            if attempt < self._BATCH_RETRIES:
                logger.debug(
                    f"  Retrying in {self._BATCH_RETRY_DELAY}s …"
                )
                time.sleep(self._BATCH_RETRY_DELAY)
            else:
                logger.warning(
                    f"get_project_ids_for_batch: giving up after "
                    f"{self._BATCH_RETRIES} attempts for "
                    f"{len(project_names)} project(s). "
                    f"They will appear as PROJECT_NOT_FOUND."
                )

    def get_latest_scan_id(self, project_id: str) -> str | None:
        """
        Return the scan ID of the most recent completed scan for *project_id*,
        or None if no scan record is available.

        Delegates to the existing get_project_last_scan() method.
        """
        logger.debug(f"Fetching latest scan ID for project {project_id}")
        scan_info = self.get_project_last_scan(project_id)
        if not scan_info:
            logger.debug(f"No completed scan found for project ID {project_id}.")
            return None

        scan_id = scan_info.get("id") or scan_info.get("scanID")
        logger.debug(f"Latest scan ID for project {project_id}: {scan_id}")
        return scan_id

    # ------------------------------------------------------------------
    # Transient-error retry helper
    # ------------------------------------------------------------------

    _TRANSIENT_RETRIES    = 3
    _TRANSIENT_RETRY_DELAY = 5   # seconds between retries

    _TRANSIENT_EXCEPTIONS = (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
        requests.exceptions.ChunkedEncodingError,
    )

    def _transient_request(self, method: str, url: str, **kwargs):
        """
        Wrapper around ``requests.request`` that retries on transient network
        errors (ConnectionError, Timeout, ChunkedEncodingError) up to
        _TRANSIENT_RETRIES times with a fixed delay between attempts.

        Returns the ``requests.Response`` on success.
        Raises the last exception if all retries are exhausted.
        """
        last_exc = None
        for attempt in range(1, self._TRANSIENT_RETRIES + 1):
            try:
                return requests.request(method, url, verify=self.verify, **kwargs)
            except self._TRANSIENT_EXCEPTIONS as exc:
                last_exc = exc
                logger.debug(
                    f"Transient network error on attempt {attempt}/"
                    f"{self._TRANSIENT_RETRIES} [{method} {url}]: {exc}"
                )
                if attempt < self._TRANSIENT_RETRIES:
                    logger.debug(f"  Retrying in {self._TRANSIENT_RETRY_DELAY}s …")
                    time.sleep(self._TRANSIENT_RETRY_DELAY)
        raise last_exc

    def create_report(self, scan_id: str, project_id: str,
                      report_name: str = "improved-scan-report",
                      report_type: str = "cli",
                      file_format: str = "pdf") -> str | None:
        """
        Submit a report generation request for *scan_id* / *project_id*.

        Parameters
        ----------
        scan_id      : UUID of the scan to report on.
        project_id   : UUID of the owning project.
        report_name  : reportName REST parameter (default: ``improved-scan-report``).
        report_type  : reportType REST parameter (default: ``cli``).
        file_format  : fileFormat REST parameter (default: ``pdf``).

        Returns
        -------
        str | None
            The ``reportId`` string returned by the API, or None on failure.
        """
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/reports"
        headers = {
            "Accept": "application/json; version=1.0",
            "Authorization": f"Bearer {self.bearer_token}",
            "Content-Type": "application/json; version=1.0",
        }
        payload = {
            "reportName": report_name,
            "reportType": report_type,
            "fileFormat": file_format,
            "data": {
                "scanId":    scan_id,
                "projectId": project_id,
            },
        }

        logger.debug(
            f"Creating report '{report_name}' (type={report_type}, "
            f"format={file_format}) for scan {scan_id} / project {project_id}"
        )

        try:
            response = self._transient_request(
                "POST", url, headers=headers, json=payload
            )
        except self._TRANSIENT_EXCEPTIONS as exc:
            logger.debug(f"create_report: network error after retries – {exc}")
            return None

        # 202 Accepted is the documented success response for async report submission.
        # 200/201 are also tolerated for forward-compatibility.
        if response.status_code in (200, 201, 202):
            body = response.json()
            # The documented response shape is {"reportId": "<uuid>"}.
            # Fall back to "id" only as a safety net for non-standard responses.
            report_id = body.get("reportId") or body.get("id")
            logger.debug(
                f"Report submitted (HTTP {response.status_code}) – reportId: {report_id}"
            )
            return report_id

        logger.debug(
            f"Error creating report for scan {scan_id}: "
            f"{response.status_code} - {response.text}"
        )
        return None

    def poll_report_status(self, report_id: str,
                           interval: int = 15,
                           timeout: int = 300) -> bool:
        """
        Poll ``GET /api/reports/{reportId}`` until the report is complete.

        Response shape::

            {
                "reportId": "<uuid>",
                "status":   "requested" | "started" | "completed" | "failed",
                "url":      "<string>"
            }

        Transient network errors within a poll attempt are retried via
        _transient_request; a failed attempt counts as a non-completed poll
        cycle and the next sleep+retry loop iteration follows normally.

        Parameters
        ----------
        report_id : Report UUID returned by create_report().
        interval  : Seconds between polls (default: 15).
        timeout   : Maximum total seconds to wait (default: 300).

        Returns
        -------
        bool
            True when status is ``completed``; False on ``failed`` or timeout.
        """
        url = f"{self.ast_host}/api/reports/{report_id}"
        deadline = time.time() + timeout
        attempt = 0

        logger.debug(
            f"Polling report {report_id} "
            f"(interval={interval}s, timeout={timeout}s)"
        )

        while time.time() < deadline:
            attempt += 1
            self.bearer_token = self.get_bearer_token()
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.bearer_token}",
            }

            try:
                response = self._transient_request(
                    "GET", url, headers=headers, timeout=30
                )
            except self._TRANSIENT_EXCEPTIONS as exc:
                logger.debug(
                    f"poll_report_status: network error on attempt {attempt} – {exc}; "
                    f"will retry after {interval}s"
                )
                time.sleep(interval)
                continue

            if response.status_code != 200:
                logger.debug(
                    f"poll_report_status: HTTP {response.status_code} on attempt "
                    f"{attempt} – {response.text}"
                )
                time.sleep(interval)
                continue

            body = response.json()
            status = (body.get("status") or "").lower()

            logger.debug(
                f"Report {report_id} status (attempt #{attempt}): '{status}'"
            )

            if status == "completed":
                logger.debug(f"Report {report_id} completed after {attempt} poll(s).")
                return True

            if status == "failed":
                logger.debug(f"Report {report_id} failed.")
                return False

            # status is 'requested' or 'started' — keep waiting
            time.sleep(interval)

        logger.debug(
            f"Timed out waiting for report {report_id} after {timeout}s."
        )
        return False

    def download_report(self, report_id: str, dest_path: str) -> bool:
        """
        Download a completed report via ``GET /api/reports/{reportId}/download``.

        Parameters
        ----------
        report_id : Report UUID returned by create_report().
        dest_path : Local filesystem path (including filename) to write to.

        Returns
        -------
        bool
            True on success, False if the HTTP call fails.
        """
        import pathlib
        self.bearer_token = self.get_bearer_token()
        url = f"{self.ast_host}/api/reports/{report_id}/download"
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
        }

        logger.debug(f"Downloading report {report_id} -> {dest_path}")

        try:
            response = self._transient_request(
                "GET", url, headers=headers, timeout=120, stream=True
            )
        except self._TRANSIENT_EXCEPTIONS as exc:
            logger.debug(f"download_report: network error after retries – {exc}")
            return False

        if response.status_code != 200:
            logger.debug(
                f"Error downloading report {report_id}: "
                f"{response.status_code} - {response.text}"
            )
            return False

        pathlib.Path(dest_path).parent.mkdir(parents=True, exist_ok=True)
        bytes_written = 0
        with open(dest_path, "wb") as fh:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    fh.write(chunk)
                    bytes_written += len(chunk)

        logger.debug(
            f"Report written to '{dest_path}' ({bytes_written} bytes)."
        )
        return True


# ---------------------------------------------------------------------------
# CxSASTSOAPClient
# ---------------------------------------------------------------------------
# Authenticates against the CxSAST REST identity endpoint (same OAuth2
# resource-owner-password flow used by the Go exporter) and then issues
# SOAP calls to CxWebService.asmx.
#
# The primary use-case exposed here is extracting *custom* queries from
# CxSAST (i.e. query groups whose PackageType is NOT "Cx") and writing them
# to disk under a local `queries_data/` folder rather than bundling them
# into a zip archive.
#
# Usage:
#   client = CxSASTSOAPClient("https://your-sast-host", "admin", "secret")
#   client.authenticate()
#   client.export_custom_queries()          # writes queries_data/ to disk
#   client.export_custom_states()           # writes queries_data/ to disk
# ---------------------------------------------------------------------------

import os
import xml.etree.ElementTree as ET
from xml.dom import minidom


class CxSASTSOAPClient:
    """Thin SOAP client for CxSAST with a REST-based OAuth2 auth flow."""

    # CxSAST resource-owner client credentials (public, shipped with the product)
    _CLIENT_ID = "resource_owner_sast_client"
    _CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"
    _SCOPE = "access_control_api sast_api"

    # PackageType value used by built-in (non-custom) Checkmarx query groups
    _CX_PACKAGE_TYPE = "Cx"

    # Default result states shipped with every CxSAST installation
    _DEFAULT_STATES = [
        {"ResultName": "To Verify",                 "ResultID": 0, "ResultPermission": "set-result-state-toverify"},
        {"ResultName": "Not Exploitable",           "ResultID": 1, "ResultPermission": "set-result-state-notexploitable"},
        {"ResultName": "Confirmed",                 "ResultID": 2, "ResultPermission": "set-result-state-confirmed"},
        {"ResultName": "Urgent",                    "ResultID": 3, "ResultPermission": "set-result-state-urgent"},
        {"ResultName": "Proposed Not Exploitable",  "ResultID": 4, "ResultPermission": "set-result-state-proposednotexploitable"},
    ]

    def __init__(self, cxsast_host: str, username: str, password: str, verify_ssl: bool = True):
        """
        Parameters
        ----------
        cxsast_host : str
            Base URL of the CxSAST server, e.g. ``https://cxsast.example.com``.
            No trailing slash.
        username : str
            CxSAST username.
        password : str
            CxSAST password.
        verify_ssl : bool
            Pass ``False`` to disable TLS certificate verification (not recommended
            in production).
        """
        self.cxsast_host = cxsast_host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

        self._access_token: str | None = None
        self._token_type: str = "Bearer"
        self._token_expiration: datetime | None = None

        self._soap_url = f"{self.cxsast_host}/Cxwebinterface/Portal/CxWebService.asmx"

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Obtain an OAuth2 access token from CxSAST and cache it."""
        url = f"{self.cxsast_host}/CxRestAPI/auth/identity/connect/token"
        data = {
            "username": self.username,
            "password": self.password,
            "grant_type": "password",
            "scope": self._SCOPE,
            "client_id": self._CLIENT_ID,
            "client_secret": self._CLIENT_SECRET,
        }
        response = requests.post(url, data=data, verify=self.verify_ssl)
        if response.status_code != 200:
            raise RuntimeError(
                f"CxSAST authentication failed [{response.status_code}]: {response.text}"
            )
        body = response.json()
        self._access_token = body["access_token"]
        self._token_type = body.get("token_type", "Bearer")
        expires_in = body.get("expires_in", 3600)
        # Refresh 5 minutes before actual expiry
        self._token_expiration = datetime.now() + timedelta(seconds=expires_in - 300)
        logger.debug("CxSASTSOAPClient: authenticated successfully")

    def _ensure_authenticated(self) -> None:
        """Re-authenticate if the token is missing or about to expire."""
        if self._access_token is None or (
            self._token_expiration and datetime.now() >= self._token_expiration
        ):
            self.authenticate()

    @property
    def _auth_header(self) -> str:
        self._ensure_authenticated()
        return f"{self._token_type} {self._access_token}"

    # Namespace that CxSAST puts on all response body elements
    _CX_NS = "http://Checkmarx.com"

    @staticmethod
    def _q(tag: str, ns: str = "http://Checkmarx.com") -> str:
        """Return a Clark-notation qualified tag: ``{namespace}tag``."""
        return f"{{{ns}}}{tag}"

    def _find(self, element: ET.Element, tag: str) -> ET.Element | None:
        """
        Find a direct child by local tag name, trying the CxSAST namespace
        first then falling back to no namespace.

        CxSAST response elements carry ``xmlns="http://Checkmarx.com"`` so
        Python's ElementTree represents every tag as
        ``{http://Checkmarx.com}TagName``.  Plain ``find("TagName")`` returns
        ``None`` — this helper abstracts that away.
        """
        return element.find(self._q(tag)) or element.find(tag)

    def _findall(self, element: ET.Element, tag: str) -> list[ET.Element]:
        """findall equivalent of ``_find``."""
        result = element.findall(self._q(tag))
        if not result:
            result = element.findall(tag)
        return result

    def _findtext(self, element: ET.Element, tag: str) -> str:
        """findtext equivalent of ``_find``, always returns a string."""
        return (
            element.findtext(self._q(tag))
            or element.findtext(tag)
            or ""
        )

    # ------------------------------------------------------------------
    # Low-level SOAP transport
    # ------------------------------------------------------------------

    def _soap_call(self, soap_action: str, inner_xml: str) -> ET.Element:
        """
        Wrap *inner_xml* in a SOAP 1.2 envelope, POST it, and return the
        first child element of ``<soap:Body>`` — i.e. the response wrapper
        element such as ``<GetQueryCollectionResponse>``.

        Parameters
        ----------
        soap_action : str
            The SOAP action name, e.g. ``"GetQueryCollection"``.
        inner_xml : str
            The serialised XML payload that goes inside ``<soap:Body>``.

        Returns
        -------
        xml.etree.ElementTree.Element
            The first child of ``<soap:Body>`` in the response, with
            ``{http://Checkmarx.com}`` namespaces intact on all descendants.
        """
        envelope = (
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"'
            ' xmlns:chec="http://Checkmarx.com">'
            "<soap:Header/>"
            f"<soap:Body>{inner_xml}</soap:Body>"
            "</soap:Envelope>"
        )
        headers = {
            "Authorization": self._auth_header,
            "Content-Type": (
                f"application/soap+xml;charset=UTF-8;"
                f"action=http://Checkmarx.com/{soap_action}"
            ),
        }
        response = requests.post(
            self._soap_url,
            data=envelope.encode("utf-8"),
            headers=headers,
            verify=self.verify_ssl,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"SOAP call '{soap_action}' failed [{response.status_code}]: "
                f"{response.text[:500]}"
            )

        root = ET.fromstring(response.content)
        soap_ns = {"s": "http://www.w3.org/2003/05/soap-envelope"}
        body = root.find("s:Body", soap_ns)
        if body is None:
            body = root.find("Body")
        if body is None or len(body) == 0:
            raise RuntimeError(
                f"SOAP call '{soap_action}': could not locate Body in response"
            )
        return body[0]  # e.g. {http://Checkmarx.com}GetQueryCollectionResponse

    # ------------------------------------------------------------------
    # SOAP operations
    # ------------------------------------------------------------------

    def get_query_collection(self) -> ET.Element:
        """
        Call ``GetQueryCollection`` and return the
        ``<GetQueryCollectionResponse>`` element.

        Raises ``RuntimeError`` if the SOAP response indicates failure.
        """
        inner_xml = "<chec:GetQueryCollection/>"
        response_el = self._soap_call("GetQueryCollection", inner_xml)
        result = self._find(response_el, "GetQueryCollectionResult")
        if result is None:
            raise RuntimeError("GetQueryCollection: GetQueryCollectionResult element not found")
        is_ok = self._findtext(result, "IsSuccesfull")
        if is_ok.lower() != "true":
            raise RuntimeError(f"GetQueryCollection: IsSuccesfull={is_ok!r}")
        logger.debug("CxSASTSOAPClient: GetQueryCollection succeeded")
        return response_el

    def get_result_state_list(self) -> ET.Element:
        """
        Call ``GetResultStateList`` and return the
        ``<GetResultStateListResponse>`` element.
        """
        inner_xml = "<chec:GetResultStateList/>"
        response_el = self._soap_call("GetResultStateList", inner_xml)
        logger.debug("CxSASTSOAPClient: GetResultStateList succeeded")
        return response_el

    # ------------------------------------------------------------------
    # Custom-query extraction helpers
    # ------------------------------------------------------------------

    def _get_custom_query_groups(self) -> list[ET.Element]:
        """
        Return a list of ``<CxWSQueryGroup>`` elements whose
        ``<PackageType>`` is *not* ``"Cx"`` (i.e. custom query groups).
        """
        response_el = self.get_query_collection()

        # GetQueryCollectionResponse > GetQueryCollectionResult >
        # QueryGroups > CxWSQueryGroup
        result = self._find(response_el, "GetQueryCollectionResult")
        query_groups_el = self._find(result, "QueryGroups")
        if query_groups_el is None:
            logger.debug("CxSASTSOAPClient: no QueryGroups element found")
            return []

        custom_groups = []
        for group in self._findall(query_groups_el, "CxWSQueryGroup"):
            pkg_type = self._findtext(group, "PackageType")
            if pkg_type != self._CX_PACKAGE_TYPE:
                custom_groups.append(group)

        logger.debug(
            f"CxSASTSOAPClient: found {len(custom_groups)} custom query group(s)"
        )
        return custom_groups

    def _get_custom_states(self) -> list[dict]:
        """
        Return only the *custom* result states — those that are not present
        in the default set shipped with CxSAST.

        Mirrors the logic in the Go exporter's ``GetCustomStatesList``:
        - If a state has the same ResultID as a default state but a different
          name, it is treated as an overwrite and assigned a new ID.
        - If a state has the same name as a default state but a different ID,
          it is also treated as an overwrite and assigned a new ID.
        - Anything not in the default set is kept as-is.
        """
        response_el = self.get_result_state_list()

        result = self._find(response_el, "GetResultStateListResult")
        if result is None:
            result = response_el
        state_list_el = self._find(result, "ResultStateList")
        if state_list_el is None:
            return []

        # Build lookup maps for default states
        default_by_id: dict[int, dict] = {s["ResultID"]: s for s in self._DEFAULT_STATES}
        default_by_name: dict[str, dict] = {s["ResultName"]: s for s in self._DEFAULT_STATES}

        # Parse all states from the SOAP response
        raw_states: list[dict] = []
        for state_el in self._findall(state_list_el, "ResultState"):
            raw_states.append({
                "ResultName": self._findtext(state_el, "ResultName"),
                "ResultID": int(self._findtext(state_el, "ResultID") or "0"),
                "ResultPermission": self._findtext(state_el, "ResultPermission"),
            })

        # Determine the highest ID for assigning new IDs to overwrites
        max_id = max(
            (s["ResultID"] for s in raw_states),
            default=4,
        )
        max_id = max(max_id, 4)  # floor at the default maximum

        custom_states: list[dict] = []
        for state in raw_states:
            rid = state["ResultID"]
            rname = state["ResultName"]

            if rid in default_by_id:
                if rname != default_by_id[rid]["ResultName"]:
                    # Overwrite by ID: different name -> reassign
                    max_id += 1
                    logger.debug(
                        f"Detected overwrite for ID {rid}: "
                        f"default name '{default_by_id[rid]['ResultName']}', "
                        f"SOAP name '{rname}' -> reassigning to ID {max_id}"
                    )
                    custom_states.append({
                        "ResultName": rname,
                        "ResultID": max_id,
                        "ResultPermission": state["ResultPermission"],
                    })
                # else: matches a default state exactly — skip
            elif rname in default_by_name:
                if rid != default_by_name[rname]["ResultID"]:
                    # Overwrite by name: different ID -> reassign
                    max_id += 1
                    logger.debug(
                        f"Detected overwrite for state '{rname}': "
                        f"default ID {default_by_name[rname]['ResultID']}, "
                        f"SOAP ID {rid} -> reassigning to ID {max_id}"
                    )
                    custom_states.append({
                        "ResultName": rname,
                        "ResultID": max_id,
                        "ResultPermission": state["ResultPermission"],
                    })
                # else: matches a default state exactly — skip
            else:
                # Genuinely new custom state
                custom_states.append(state)

        custom_states.sort(key=lambda s: s["ResultID"])
        logger.debug(
            f"CxSASTSOAPClient: identified {len(custom_states)} custom state(s)"
        )
        return custom_states

    # ------------------------------------------------------------------
    # Disk-export helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pretty_xml(element: ET.Element) -> str:
        """Return a pretty-printed XML string for *element*."""
        raw = ET.tostring(element, encoding="unicode")
        return minidom.parseString(raw).toprettyxml(indent="    ")

    def export_custom_queries(self, output_dir: str = "queries_data") -> str:
        """
        Fetch all custom query groups from CxSAST and write them to disk.

        Each custom query group is serialised as an individual XML file named
        ``<PackageFullName>.xml`` (with path separators replaced by ``__``).
        A summary manifest ``custom_queries_manifest.json`` is also written.

        Parameters
        ----------
        output_dir : str
            Directory to write files into.  Created if it does not exist.

        Returns
        -------
        str
            Absolute path to the output directory.
        """
        os.makedirs(output_dir, exist_ok=True)
        custom_groups = self._get_custom_query_groups()

        manifest = []
        for group in custom_groups:
            full_name = (
                self._findtext(group, "PackageFullName")
                or self._findtext(group, "Name")
                or "unknown"
            )
            # Sanitise the name for use as a filename
            safe_name = full_name.replace("/", "__").replace("\\", "__").replace(" ", "_")
            filename = f"{safe_name}.xml"
            filepath = os.path.join(output_dir, filename)

            xml_str = self._pretty_xml(group)
            with open(filepath, "w", encoding="utf-8") as fh:
                fh.write(xml_str)

            queries_el = self._find(group, "Queries")
            query_count = len(self._findall(queries_el, "CxWSQuery")) if queries_el is not None else 0
            manifest.append({
                "PackageFullName": full_name,
                "PackageType": self._findtext(group, "PackageType"),
                "LanguageName": self._findtext(group, "LanguageName"),
                "ProjectId": self._findtext(group, "ProjectId"),
                "IsReadOnly": self._findtext(group, "IsReadOnly"),
                "QueryCount": query_count,
                "File": filename,
            })
            logger.debug(
                f"CxSASTSOAPClient: wrote {query_count} queries -> {filepath}"
            )

        # Write manifest
        manifest_path = os.path.join(output_dir, "custom_queries_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)

        logger.debug(
            f"CxSASTSOAPClient: exported {len(custom_groups)} custom query group(s) "
            f"to '{output_dir}'"
        )
        return os.path.abspath(output_dir)

    def export_custom_states(self, output_dir: str = "queries_data") -> str:
        """
        Fetch all custom result states from CxSAST and write them to disk.

        Writes a single file ``custom_states.json`` containing the list of
        custom states (states that are not part of the CxSAST default set).

        Parameters
        ----------
        output_dir : str
            Directory to write files into.  Created if it does not exist.

        Returns
        -------
        str
            Absolute path to the output directory.
        """
        os.makedirs(output_dir, exist_ok=True)
        custom_states = self._get_custom_states()

        filepath = os.path.join(output_dir, "custom_states.json")
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(custom_states, fh, indent=2)

        logger.debug(
            f"CxSASTSOAPClient: exported {len(custom_states)} custom state(s) "
            f"to '{filepath}'"
        )
        return os.path.abspath(output_dir)

    def export_queries_data(self, output_dir: str = "queries_data") -> str:
        """
        Convenience method: export both custom queries and custom states in
        one call.

        Parameters
        ----------
        output_dir : str
            Directory to write files into.  Created if it does not exist.

        Returns
        -------
        str
            Absolute path to the output directory.
        """
        self.export_custom_queries(output_dir=output_dir)
        self.export_custom_states(output_dir=output_dir)
        logger.debug(
            f"CxSASTSOAPClient: queries_data export complete -> '{output_dir}'"
        )
        return os.path.abspath(output_dir)