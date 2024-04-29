
# AUTOGENERATED DO NOT EDIT
# Autogenerated using the pat_regex_generator dev tool

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
    r"AWS\.SecurityFindingFormat|"
    r"AWS\.TransitGatewayFlow|"
    r"AWS\.VPCDns|"
    r"AWS\.VPCFlow|"
    r"AWS\.WAFWebACL|"
    r"AlphaSOC\.Alert|"
    r"Amazon\.EKS\.Audit|"
    r"Amazon\.EKS\.Authenticator|"
    r"Anomali\.Indicator|"
    r"Apache\.AccessCombined|"
    r"Apache\.AccessCommon|"
    r"AppOmni\.Alerts|"
    r"AppOmni\.Events|"
    r"AppOmni\.Policy|"
    r"Asana\.Audit|"
    r"Atlassian\.Audit|"
    r"Auth0\.Events|"
    r"Azure\.Audit|"
    r"Azure\.DefenderAlerts|"
    r"Azure\.MonitorActivity|"
    r"Bitwarden\.Events|"
    r"Box\.Event|"
    r"CarbonBlack\.AlertV2|"
    r"CarbonBlack\.Audit|"
    r"CarbonBlack\.EndpointEvent|"
    r"CarbonBlack\.WatchlistHit|"
    r"CiscoUmbrella\.CloudFirewall|"
    r"CiscoUmbrella\.DNS|"
    r"CiscoUmbrella\.IP|"
    r"CiscoUmbrella\.Proxy|"
    r"Cloudflare\.Audit|"
    r"Cloudflare\.Firewall|"
    r"Cloudflare\.HttpRequest|"
    r"Cloudflare\.Spectrum|"
    r"Cloudflare\.ZeroTrust\.RData|"
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
    r"Envoy\.Access|"
    r"Fastly\.Access|"
    r"Fluentd\.Syslog3164|"
    r"Fluentd\.Syslog5424|"
    r"GCP\.AuditLog|"
    r"GCP\.HTTPLoadBalancer|"
    r"GSuite\.ActivityEvent|"
    r"GSuite\.DirectoryUsers|"
    r"GSuite\.Reports|"
    r"GitHub\.Audit|"
    r"GitHub\.Webhook|"
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
    r"Jamfpro\.ComplianceReporter|"
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
    r"Nginx\.Error|"
    r"Notion\.AuditLogs|"
    r"OCSF\.AccountChange|"
    r"OCSF\.ApiActivity|"
    r"OCSF\.ApplicationLifecycle|"
    r"OCSF\.Authentication|"
    r"OCSF\.AuthorizeSession|"
    r"OCSF\.BaseEvent|"
    r"OCSF\.ComplianceFinding|"
    r"OCSF\.ConfigState|"
    r"OCSF\.DatastoreActivity|"
    r"OCSF\.DetectionFinding|"
    r"OCSF\.DeviceConfigStateChange|"
    r"OCSF\.DhcpActivity|"
    r"OCSF\.DnsActivity|"
    r"OCSF\.EmailActivity|"
    r"OCSF\.EmailFileActivity|"
    r"OCSF\.EmailUrlActivity|"
    r"OCSF\.EntityManagement|"
    r"OCSF\.FileActivity|"
    r"OCSF\.FileHosting|"
    r"OCSF\.FtpActivity|"
    r"OCSF\.GroupManagement|"
    r"OCSF\.HttpActivity|"
    r"OCSF\.IncidentFinding|"
    r"OCSF\.InventoryInfo|"
    r"OCSF\.KernelActivity|"
    r"OCSF\.KernelExtension|"
    r"OCSF\.MemoryActivity|"
    r"OCSF\.ModuleActivity|"
    r"OCSF\.NetworkActivity|"
    r"OCSF\.NetworkFileActivity|"
    r"OCSF\.NtpActivity|"
    r"OCSF\.PatchState|"
    r"OCSF\.ProcessActivity|"
    r"OCSF\.RdpActivity|"
    r"OCSF\.ScanActivity|"
    r"OCSF\.ScheduledJobActivity|"
    r"OCSF\.SecurityFinding|"
    r"OCSF\.SmbActivity|"
    r"OCSF\.SshActivity|"
    r"OCSF\.UserAccess|"
    r"OCSF\.UserInventory|"
    r"OCSF\.VulnerabilityFinding|"
    r"OCSF\.WebResourceAccessActivity|"
    r"OCSF\.WebResourcesActivity|"
    r"OCSF\.WinPrefetchInfo|"
    r"OCSF\.WinRegistryKeyActivity|"
    r"OCSF\.WinRegistryKeyInfo|"
    r"OCSF\.WinRegistryValueActivity|"
    r"OCSF\.WinRegistryValueInfo|"
    r"OCSF\.WinResourceActivity|"
    r"OCSF\.WinprefetchInfo|"
    r"OCSF\.WinregistryKeyActivity|"
    r"OCSF\.WinregistryKeyInfo|"
    r"OCSF\.WinregistryValueActivity|"
    r"OCSF\.WinregistryValueInfo|"
    r"OCSF\.WinresourceActivity|"
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
    r"Proofpoint\.Event|"
    r"PushSecurity\.Activity|"
    r"PushSecurity\.AttackDetection|"
    r"PushSecurity\.Entities|"
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
    r"TrailDiscover\.CloudTrail|"
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

RESOURCE_TYPE_REGEX = Regex(
    r"^("
    r"AWS\.ACM\.Certificate|"
    r"AWS\.CloudFormation\.Stack|"
    r"AWS\.CloudTrail|"
    r"AWS\.CloudTrail\.Meta|"
    r"AWS\.CloudWatch\.LogGroup|"
    r"AWS\.Config\.Recorder|"
    r"AWS\.Config\.Recorder\.Meta|"
    r"AWS\.DynamoDB\.Table|"
    r"AWS\.EC2\.AMI|"
    r"AWS\.EC2\.Instance|"
    r"AWS\.EC2\.NetworkACL|"
    r"AWS\.EC2\.SecurityGroup|"
    r"AWS\.EC2\.VPC|"
    r"AWS\.EC2\.Volume|"
    r"AWS\.ECS\.Cluster|"
    r"AWS\.EKS\.Cluster|"
    r"AWS\.ELBV2\.ApplicationLoadBalancer|"
    r"AWS\.GuardDuty\.Detector|"
    r"AWS\.GuardDuty\.Detector\.Meta|"
    r"AWS\.IAM\.Group|"
    r"AWS\.IAM\.Policy|"
    r"AWS\.IAM\.Role|"
    r"AWS\.IAM\.RootUser|"
    r"AWS\.IAM\.User|"
    r"AWS\.KMS\.Key|"
    r"AWS\.Lambda\.Function|"
    r"AWS\.PasswordPolicy|"
    r"AWS\.RDS\.Instance|"
    r"AWS\.Redshift\.Cluster|"
    r"AWS\.Route53\.HostedZone|"
    r"AWS\.Route53Domains|"
    r"AWS\.S3\.Bucket|"
    r"AWS\.WAF\.Regional\.WebACL|"
    r"AWS\.WAF\.WebACL|"
    r")$"
)
