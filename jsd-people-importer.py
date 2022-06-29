"""
This script creates customers in a Jira Service Desk instance from an LDAP query.
"""

# Copyright 2020 Dalton Durst
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import json
import sys
from collections import namedtuple
from json.decoder import JSONDecodeError
from typing import List

import ldap
import requests
from ldap.controls import SimplePagedResultsControl

from conf import (
    JIRA_KEY,
    JIRA_SERVICEDESK,
    JIRA_URL,
    JIRA_USERNAME,
    LDAP_BIND_PASSWORD,
    LDAP_BIND_URI,
    LDAP_BIND_USERNAME,
    LDAP_FILTER,
    LDAP_INSECURE,
    LDAP_SEARCH_DN_LIST,
)

JIRA_AUTH = requests.auth.HTTPBasicAuth(JIRA_USERNAME, JIRA_KEY)

SESSION = requests.Session()

User = namedtuple("User", ["email", "last_name", "first_name"])
JiraUser = namedtuple(
    "JiraUser", ["accountId", "accountType", "emailAddress", "displayName", "active"]
)


def eprint(*args, **kwargs):
    """Like print, but outputs to stderr."""
    print(*args, file=sys.stderr, **kwargs)


def results_for_dn(directory: ldap.ldapobject, base_dn: str, filter: str) -> List[User]:
    """Returns a list of User objects found in the directory object for filter

    :param directory: A ldap.LDAPObject that has already been bound to a
        directory.

    :param base_dn: The base of the directory tree to run the search filter
        against.

    :param filter: The LDAP search filter to run on base_dn using directory.
    """
    req_ctrl = SimplePagedResultsControl(True, size=5000, cookie="")

    known_ldap_resp_ctrls = {
        SimplePagedResultsControl.controlType: SimplePagedResultsControl,
    }

    # Send search request
    msgid = directory.search_ext(
        base_dn, ldap.SCOPE_SUBTREE, filterstr=LDAP_FILTER, serverctrls=[req_ctrl]
    )

    results = []
    while True:
        __, result_data, __, serverctrls = directory.result3(
            msgid, resp_ctrl_classes=known_ldap_resp_ctrls
        )

        results.extend(
            [
                User(
                    ldap_entry["mail"][0].decode(),
                    ldap_entry["sn"][0].decode(),
                    ldap_entry["givenName"][0].decode(),
                )
                for __, ldap_entry in result_data
            ]
        )

        page_controls = [
            control
            for control in serverctrls
            if control.controlType == SimplePagedResultsControl.controlType
        ]
        if page_controls:
            if page_controls[0].cookie:
                # Copy cookie from response control to request control
                req_ctrl.cookie = page_controls[0].cookie
                msgid = directory.search_ext(
                    base_dn,
                    ldap.SCOPE_SUBTREE,
                    filterstr=LDAP_FILTER,
                    serverctrls=[req_ctrl],
                )
            else:
                break
        else:
            eprint("Warning: Server ignores RFC 2696 control.")
            break

    return results


def create_jira_customer(user: User):
    """ Creates a customer in Jira Service Desk and adds it to a project

    :param user: A User object which will be used to create the Jira user.

    This function uses the following module variables:

    * SESSION must be a requests.Session instance
    * JIRA_AUTH must be a requests.auth interface instance
    * JIRA_URL must be the full base URL of a Jira Service Desk server.
    * JIRA_SERVICEDESK must be the ID of a Jira Service Desk project
    """
    eprint("Attempting to create", user.email)

    payload = json.dumps(
        {
            "displayName": "{}, {}".format(user.last_name, user.first_name),
            "email": user.email,
        }
    )

    new_user_request = SESSION.post(
        JIRA_URL + "/rest/servicedeskapi/customer",
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        auth=JIRA_AUTH,
    )

    try:
        new_user_request.raise_for_status()
    except requests.exceptions.RequestException as e:
        eprint("Failed to create user with email", user.email)
        eprint(e)
        eprint(new_user_request.text)
        return

    print(user.email)
    return user.email


def get_jira_users() -> List[JiraUser]:
    """Returns the email address of every user in Jira.

    This function's results include customers and Atlassian users. They also
    include *all* users, not just the users on a certain service desk. This
    information can be used to determine which users you should create next.

    This function uses the following module variables:

    * SESSION must be a requests.Session instance
    * JIRA_AUTH must be a requests.auth interface instance
    * JIRA_URL must be the full base URL of a Jira Service Desk server.
    """

    url = "{base}/rest/api/3/users".format(base=JIRA_URL)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    users = []
    start = 0
    while True:
        r = SESSION.get(url, auth=JIRA_AUTH, headers=headers, params={"startAt": start})
        this_page = r.json()
        this_page_users = []
        for user in this_page:
            try:
                this_page_users.append(
                    JiraUser(
                        accountId=user["accountId"],
                        accountType=user["accountType"],
                        emailAddress=user.get("emailAddress", None),
                        displayName=user["displayName"],
                        active=user["active"],
                    )
                )
            except KeyError as e:
                eprint("Failed to process a user record, ignoring it, here is its json:")
                eprint(user)
                eprint("Here is the exception:")
                eprint(e)
                continue

        users.extend(this_page_users)

        if len(this_page) == 0:
            break
        start += len(this_page)

    return users


def add_users_to_project(users: List[JiraUser], project: str):
    """Adds users to project as customers, if they are not already added.

    This function uses the following module variables:

    * SESSION must be a requests.Session instance
    * JIRA_AUTH must be a requests.auth interface instance
    * JIRA_URL must be the full base URL of a Jira Service Desk server.
    """

    url = "{base}/rest/servicedeskapi/servicedesk/{id}/customer".format(base=JIRA_URL, id=JIRA_SERVICEDESK)

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    body = json.dumps({
        "accountIds": [user.accountId for user in users]
    })

    r = SESSION.post(url, auth=JIRA_AUTH, headers=headers, data=body)

    if r.status_code == 504:
        eprint("Jira reported a 504 Gateway Timeout when adding users to project.")
        eprint("Usually this is not a failure and the customers are added to the project anyway.")
        return

    r.raise_for_status()


def main():

    eprint("Binding to LDAP...")
    if LDAP_INSECURE:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    directory = ldap.initialize(LDAP_BIND_URI)
    directory.protocol_version = 3
    directory.simple_bind_s(who=LDAP_BIND_USERNAME, cred=LDAP_BIND_PASSWORD)

    eprint("Searching directory for users...")
    ldap_users = []
    for base_dn in LDAP_SEARCH_DN_LIST:
        eprint("Searching DN", base_dn, "with filter", LDAP_FILTER)
        ldap_users.extend(results_for_dn(directory, base_dn, LDAP_FILTER))

    directory.unbind_s()
    directory = None

    eprint("Total LDAP users:", len(ldap_users))
    eprint("Asking Jira for its customer list...")

    preexisting_jira_users = get_jira_users()
    preexisting_jira_user_emails = [user.emailAddress.casefold() for user in preexisting_jira_users if user.emailAddress]

    eprint("Total Jira users:", len(preexisting_jira_users))

    missing_jira_users = [
        user
        for user in ldap_users
        if user.email.casefold() not in frozenset(preexisting_jira_user_emails)
    ]

    eprint("Users to create:", len(missing_jira_users))

    results = map(create_jira_customer, missing_jira_users)

    eprint("Done. Created users:", len([user for user in results if user]))
    eprint(
        "Next, will assign created customers to the {} project...".format(JIRA_SERVICEDESK)
    )

    refreshed_jira_users = get_jira_users()
    add_users_to_project(refreshed_jira_users, JIRA_SERVICEDESK)

    eprint("Done! All customers were successfully added to the service desk.")


if __name__ == "__main__":
    main()
