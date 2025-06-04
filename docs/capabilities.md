# Built-in Capabilities

Each integration plugin can expose **capabilities** – named groups of rules that map to common API actions. Assigning a capability in `allowlist.yaml` expands to the underlying HTTP rules automatically.

Run `go run ./cmd/allowlist list` to list capabilities from your build. For quick reference, the table below summarises the capabilities bundled with AuthTranslator.

| Integration | Capability | Parameters |
|-------------|-----------|------------|
| asana | add_comment | – |
| asana | create_task | – |
| asana | update_status | – |
| confluence | add_comment | – |
| confluence | create_page | – |
| confluence | update_page | – |
| ghe | comment | repo |
| ghe | create_issue | repo |
| ghe | update_issue | repo |
| github | comment | repo |
| github | create_issue | repo |
| github | update_issue | repo |
| gitlab | comment | project |
| gitlab | create_issue | project |
| gitlab | update_issue | project |
| jira | add_comment | – |
| jira | create_task | – |
| jira | update_status | – |
| linear | add_comment | – |
| linear | create_task | – |
| linear | update_status | – |
| monday | add_comment | – |
| monday | create_item | – |
| monday | update_status | – |
| okta | create_user | – |
| okta | deactivate_user | – |
| okta | update_user | – |
| openai | chat_completion | – |
| openai | create_embedding | – |
| openai | list_models | – |
| pagerduty | trigger_incident | – |
| pagerduty | resolve_incident | – |
| sendgrid | manage_contacts | – |
| sendgrid | send_email | – |
| sendgrid | update_template | – |
| servicenow | open_ticket | – |
| servicenow | query_status | – |
| servicenow | update_ticket | – |
| slack | post_channels_as | username, channels |
| slack | post_public_as | username |
| stripe | create_charge | – |
| stripe | create_customer | – |
| stripe | refund_charge | – |
| trufflehog | get_results | – |
| trufflehog | list_scans | – |
| trufflehog | start_scan | – |
| twilio | make_call | – |
| twilio | query_message | – |
| twilio | send_sms | – |
| zendesk | open_ticket | – |
| zendesk | query_status | – |
| zendesk | update_ticket | – |
Capabilities not listed above may be added by custom plugins. Use the CLI to discover them in your build.
