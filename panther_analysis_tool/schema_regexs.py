
from schema import Regex

LOG_TYPE_REGEX = Regex(
    r"^("
    r"AWS\.ALB|"
    r"AWS\.AuroraMySQLAudit|"
    r"AWS\.CloudTrail|"
    r"AWS\.CloudTrailDigest|"
    r"AWS\.CloudTrailInsight|"
    r"AWS\.CloudWatchEvents|"
    r"AWS\.Config|"
    r"AWS\.GuardDuty|"
    r"AWS\.S3ServerAccess|"
    r"AWS\.TransitGatewayFlow|"
    r"AWS\.VPCDns|"
    r"AWS\.VPCFlow|"
    r"AWS\.WAFWebACL|"
    r"AlphaSOC\.Alert|"
    r"Amazon\.EKS\.Audit|"
    r"Amazon\.EKS\.Authenticator|"
    r"Apache\.AccessCombined|"
    r"Apache\.AccessCommon|"
    r"Asana\.Audit|"
    r"Atlassian\.Audit|"
    r"Auth0\.Events|"
    r"Azure\.Audit|"
    r"Azure\.SignIn|"
    r"Bitwarden\.Events|"
    r"Box\.Event|"
    r"CarbonBlack\.Audit|"
    r"CiscoUmbrella\.CloudFirewall|"
    r"CiscoUmbrella\.DNS|"
    r"CiscoUmbrella\.IP|"
    r"CiscoUmbrella\.Proxy|"
    r"Cloudflare\.Audit|"
    r"Cloudflare\.Firewall|"
    r"Cloudflare\.HttpRequest|"
    r"Cloudflare\.Spectrum|"
    r"Crowdstrike\.AIDMaster|"
    r"Crowdstrike\.ActivityAudit|"
    r"Crowdstrike\.AppInfo|"
    r"Crowdstrike\.CriticalFile|"
    r"Crowdstrike\.DNSRequest|"
    r"Crowdstrike\.DetectionSummary|"
    r"Crowdstrike\.FDREvent|"
    r"Crowdstrike\.GroupIdentity|"
    r"Crowdstrike\.ManagedAssets|"
    r"Crowdstrike\.NetworkConnect|"
    r"Crowdstrike\.NetworkListen|"
    r"Crowdstrike\.NotManagedAssets|"
    r"Crowdstrike\.ProcessRollup2|"
    r"Crowdstrike\.ProcessRollup2Stats|"
    r"Crowdstrike\.SyntheticProcessRollup2|"
    r"Crowdstrike\.Unknown|"
    r"Crowdstrike\.UserIdentity|"
    r"Crowdstrike\.UserInfo|"
    r"Crowdstrike\.UserLogonLogoff|"
    r"Docker\.Events|"
    r"Dropbox\.TeamEvent|"
    r"Duo\.Administrator|"
    r"Duo\.Authentication|"
    r"Duo\.OfflineEnrollment|"
    r"Duo\.Telephony|"
    r"Fastly\.Access|"
    r"Fluentd\.Syslog3164|"
    r"Fluentd\.Syslog5424|"
    r"GCP\.AuditLog|"
    r"GCP\.HTTPLoadBalancer|"
    r"GSuite\.ActivityEvent|"
    r"GSuite\.DirectoryUsers|"
    r"GSuite\.Reports|"
    r"GitHub\.Audit|"
    r"GitLab\.API|"
    r"GitLab\.Audit|"
    r"GitLab\.Exceptions|"
    r"GitLab\.Git|"
    r"GitLab\.Integrations|"
    r"GitLab\.Production|"
    r"Gravitational\.TeleportAudit|"
    r"GreyNoise\.Noise|"
    r"GreyNoise\.RIOT|"
    r"Heroku\.Runtime|"
    r"IPInfo\.ASNCIDR|"
    r"IPInfo\.ASNRanges|"
    r"IPInfo\.LocationCIDR|"
    r"IPInfo\.LocationRanges|"
    r"IPInfo\.PrivacyCIDR|"
    r"IPInfo\.PrivacyRanges|"
    r"Jamfpro\.Login|"
    r"Juniper\.Access|"
    r"Juniper\.Audit|"
    r"Juniper\.Firewall|"
    r"Juniper\.MWS|"
    r"Juniper\.Postgres|"
    r"Juniper\.Security|"
    r"Lacework\.AgentManagement|"
    r"Lacework\.AlertDetails|"
    r"Lacework\.AllFiles|"
    r"Lacework\.Applications|"
    r"Lacework\.ChangeFiles|"
    r"Lacework\.CloudCompliance|"
    r"Lacework\.CloudConfiguration|"
    r"Lacework\.Cmdline|"
    r"Lacework\.Connections|"
    r"Lacework\.ContainerSummary|"
    r"Lacework\.ContainerVulnDetails|"
    r"Lacework\.DNSQuery|"
    r"Lacework\.Events|"
    r"Lacework\.HostVulnDetails|"
    r"Lacework\.Image|"
    r"Lacework\.Interfaces|"
    r"Lacework\.InternalIPA|"
    r"Lacework\.MachineDetails|"
    r"Lacework\.MachineSummary|"
    r"Lacework\.NewHashes|"
    r"Lacework\.Package|"
    r"Lacework\.PodSummary|"
    r"Lacework\.ProcessSummary|"
    r"Lacework\.UserDetails|"
    r"Lacework\.UserLogin|"
    r"Linux\.Auditd|"
    r"Microsoft365\.Audit\.AzureActiveDirectory|"
    r"Microsoft365\.Audit\.Exchange|"
    r"Microsoft365\.Audit\.General|"
    r"Microsoft365\.Audit\.SharePoint|"
    r"Microsoft365\.DLP\.All|"
    r"MicrosoftGraph\.SecurityAlert|"
    r"MongoDB\.OrganizationEvent|"
    r"MongoDB\.ProjectEvent|"
    r"Netskope\.Audit|"
    r"Nginx\.Access|"
    r"Notion\.AuditLogs|"
    r"OSSEC\.EventInfo|"
    r"Okta\.Devices|"
    r"Okta\.SystemLog|"
    r"Okta\.Users|"
    r"OneLogin\.Events|"
    r"OnePassword\.AuditEvent|"
    r"OnePassword\.ItemUsage|"
    r"OnePassword\.SignInAttempt|"
    r"Osquery\.Batch|"
    r"Osquery\.Differential|"
    r"Osquery\.Snapshot|"
    r"Osquery\.Status|"
    r"Panther\.Audit|"
    r"Salesforce\.Login|"
    r"Salesforce\.LoginAs|"
    r"Salesforce\.Logout|"
    r"Salesforce\.URI|"
    r"SentinelOne\.Activity|"
    r"SentinelOne\.DeepVisibility|"
    r"SentinelOne\.DeepVisibilityV2|"
    r"Slack\.AccessLogs|"
    r"Slack\.AuditLogs|"
    r"Slack\.IntegrationLogs|"
    r"Snyk\.GroupAudit|"
    r"Snyk\.OrgAudit|"
    r"Sophos\.Central|"
    r"Suricata\.Alert|"
    r"Suricata\.Anomaly|"
    r"Suricata\.DHCP|"
    r"Suricata\.DNS|"
    r"Suricata\.FileInfo|"
    r"Suricata\.Flow|"
    r"Suricata\.HTTP|"
    r"Suricata\.SSH|"
    r"Suricata\.TLS|"
    r"Sysdig\.Audit|"
    r"Syslog\.RFC3164|"
    r"Syslog\.RFC5424|"
    r"Tailscale\.Audit|"
    r"Tailscale\.Network|"
    r"Tenable\.Vulnerability|"
    r"Tines\.Audit|"
    r"Tor\.ExitNode|"
    r"Windows\.EventLogs|"
    r"Workday\.Activity|"
    r"Workday\.SignOnAttempt|"
    r"Zeek\.CaptureLoss|"
    r"Zeek\.Conn|"
    r"Zeek\.DHCP|"
    r"Zeek\.DNS|"
    r"Zeek\.DPD|"
    r"Zeek\.Files|"
    r"Zeek\.HTTP|"
    r"Zeek\.NTP|"
    r"Zeek\.Notice|"
    r"Zeek\.OCSP|"
    r"Zeek\.Reporter|"
    r"Zeek\.SIP|"
    r"Zeek\.Software|"
    r"Zeek\.Ssh|"
    r"Zeek\.Ssl|"
    r"Zeek\.Stats|"
    r"Zeek\.Tunnel|"
    r"Zeek\.Weird|"
    r"Zeek\.X509|"
    r"Zendesk\.Audit|"
    r"Zoom\.Activity|"
    r"Zoom\.Operation|"
    r"Custom\.([A-Z][A-Za-z0-9]*)(\.[A-Z][A-Za-z0-9]*){0,5}"
    r")$"
)
