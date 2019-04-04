#!/usr/bin/python2
# -*- coding: utf-8 -*-

import ldap
import json
import datetime
import unidecode
import base64



class ADEnrichment():
    def __init__(self, conf):
        self.adurl = conf['adurl']
        self.domain = conf['domain']
        self.computer_basedn = conf['computer_basedn']
        self.person_basedn = conf['person_basedn']
        self.service_account = conf['service_account']
        self.service_account_password = conf['service_account_password']

    def asciionly(self, txt):
        result = ''.join([i if ord(i) < 128 else ' ' for i in txt])
        if not result.strip:
            return txt
        return result

    def getFiletime(self, dt):
        microseconds = dt / 10
        seconds, microseconds = divmod(microseconds, 1000000)
        days, seconds = divmod(seconds, 86400)
        return datetime.datetime(1601, 1, 1) + \
            datetime.timedelta(days, seconds, microseconds)

    def parse(self, key, val):
        bl = [
            "logonHours",
            "msExchSafeSendersHash",
            "msExchBlockedSendersHash",
            "mS-DS-ConsistencyGuid",
            "protocolSettings",
            "msExchMailboxSecurityDescriptor",
            "msExchPoliciesIncluded",
            "userCertificate",
            "objectSid",
            "msExchMailboxGuid",
            "msDS-ExternalDirectoryObjectIdprotoco	lSettings",
            "mS-DS-ConsistencyGuid ",
            "objectGUID"]
        wl = {
            "thumbnailPhoto": "base64",
            "lastLogon": "time",
            "badPasswordTime": "time",
            "lastLogonTimestamp": "time",
            "pwdLastSet": "time",
            "	ms-Mcs-AdmPwdExpirationTime": "time"}
        filter = [
            'primaryGroupID',
            'postalCode',
            'logonCount',
            'Title',
            'LastLogonDate',
            'lastLogonTimestamp',
            'manager',
            'SID',
            'Department',
            'HomePhone',
            'instanceType',
            'AuthenticationPolicy',
            'Fax',
            'title',
            'Company',
            'AccountNotDelegated',
            'objectSid',
            'mail',
            'PrincipalsAllowedToDelegateToAccount',
            'sAMAccountName',
            'POBox',
            'whenChanged',
            'directReports',
            'StreetAddress',
            'Organization',
            'Initials',
            'MobilePhone',
            'memberOf',
            'codePage',
            'l',
            'PasswordNotRequired',
            'PrimaryGroup',
            'givenName',
            'lastLogoff',
            'DisplayName',
            'employeeID',
            'MemberOf',
            'PasswordExpired',
            'UserPrincipalName',
            'State',
            'HomeDirectory',
            'homeMDB',
            'description',
            'Deleted',
            'LastKnownParent',
            'isDeleted',
            'KerberosEncryptionType',
            'DistinguishedName',
            'pwdLastSet',
            'Created',
            'OtherName',
            'Modified',
            'EmployeeID',
            'c',
            'SamAccountName',
            'ObjectCategory',
            'LockedOut',
            'DoesNotRequirePreAuth',
            'ServicePrincipalNames',
            'cn',
            'HomeDrive',
            'mailNickname',
            'adminCount',
            'PasswordNeverExpires',
            'LogonWorkstations',
            'GivenName',
            'msExchUserAccountControl',
            'name',
            'HomePage',
            'MNSLogonAccount',
            'badPasswordTime',
            'CN',
            'company',
            'SmartcardLogonRequired',
            'Enabled',
            'BadLogonCount',
            'userPrincipalName',
            'badPwdCount',
            'LastBadPasswordAttempt',
            'accountExpires',
            'TrustedToAuthForDelegation',
            'PostalCode',
            'thumbnailPhoto',
            'OfficePhone',
            'extensionAttribute5',
            'Surname',
            'AuthenticationPolicySilo',
            'Office',
            'TrustedForDelegation',
            'sAMAccountType',
            'EmailAddress',
            'mDBUseDefaults',
            'modifyTimeStamp',
            'City',
            'countryCode',
            'CannotChangePassword',
            'AccountLockoutTime',
            'CanonicalName',
            'st',
            'SIDHistory',
            'distinguishedName',
            'Division',
            'Description',
            'ObjectClass',
            'HomedirRequired',
            'department',
            'streetAddress',
            'whenCreated',
            'legacyExchangeDN',
            'lockoutTime',
            'sn',
            'extensionAttribute15',
            'Name',
            'dSCorePropagationData',
            'Country',
            'createTimeStamp',
            'telephoneNumber',
            'AccountExpirationDate',
            'displayName',
            'PasswordLastSet',
            'userAccountControl',
            'proxyAddresses',
            'msExchWhenMailboxCreated',
            'AllowReversiblePasswordEncryption',
            'lastLogon',
            'Manager',
            'EmployeeNumber',
            'msExchUserCulture',
            'ipPhone']

        if key in bl or not key.lower().strip() in filter:
            return None

        if not key in wl:
            for i in range(0, len(val)):
                val[i] = self.asciionly(val[i])

            if isinstance(val, list) and len(val) == 1:
                return (key, val[0])
            elif isinstance(val, list):
                return (key, ','.join(val).strip(","))
        else:
            if wl[key] is "time":
                return (key, format(self.getFiletime(
                    int(val[0])), '%a, %d %B %Y %H:%M:%S %Z'))
            if wl[key] is "base64":
                return (key, str(base64.b64encode(val[0])))
        return (key, val)

    def adlookup(self, subject, otype):
        ldap_obj = ldap.initialize(self.adurl)
        ldap_obj.protocol_version = ldap.VERSION3
        ldap_obj.set_option(ldap.OPT_REFERRALS, 0)
        result = ldap_obj.simple_bind_s(
            self.service_account + "@" + self.domain,
            self.service_account_password)
        basedns = None
        if otype == "computer":
            basedns = self.computer_basedn.split(";")
        elif otype == "person" or otype == "mail":
            basedns = self.person_basedn.split(";")
        else:
            return

        if result[0] == 97 and result[2] == 1:
            # ldap bind worked
            results = {}
            for basedn in basedns:
                try:
                    m = None
                    if otype == "person":
                        m = ldap_obj.search_ext_s(
                            basedn.strip(","),
                            ldap.SCOPE_SUBTREE,
                            "(SamAccountName=" + subject + ")")[0][1]
                    elif otype == "mail":
                        m = ldap_obj.search_ext_s(
                            basedn.strip(","), ldap.SCOPE_SUBTREE, "(mail=" + subject + ")")[0][1]
                    elif otype == "computer":
                        m = ldap_obj.search_ext_s(
                            basedn.strip(","), ldap.SCOPE_SUBTREE, "(Name=" + subject + ")")[0][1]
                    for i in m:
                        try:
                            parsed = self.parse(i, m[i])

                            if parsed:
                                results[parsed[0]] = parsed[1]
                            else:
                                results[i] = self.asciionly(m[i])
                        except BaseException:
                            continue
                    break
                except Exception as e:
                    # print(str(e))
                    continue
                    return {}
            return results
        return {}

    def summary(self, raw):
        return {"taxonomies": [{"predicate": "ActieDirectory Object",
                                "namespace": "ActiveDirectory", "value": raw["Name"], "level": "info"}]}

    def run(self):
        data = self.get_param('data', None, "Data is missing")
        data = data.replace("[.]", ".")
        if self.data_type in ['upn', 'mail']:
            result = self.adlookup(data.strip("<").strip(">"), 'mail')
            self.report(result)
        elif self.data_type in ['computer', 'hostname', 'fqdn', 'domain']:
            result = self.adlookup(data, 'computer')
            self.report(result)
        elif self.data_type in ['user', 'name', 'person', 'givenname', 'samid', 'ntid', 'account', 'samaccountname']:
            result = self.adlookup(data, 'person')
            self.report(result)
        else:
            self.error('invalid data type')


if __name__ == '__main__':
    ADEnrichment().run()
