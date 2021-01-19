## Quick Splunk Dashboard and savedsearches for Searching through and viewing reports of Indicators of compromise relating to SUNBURST.

## Note
[Status Indicator App](https://splunkbase.splunk.com/app/3119/) is required for the visualizations to work; however, the dashboard can easily be adjusted to support native visualizations.

## Full Guide
1. Configure automatic ingest of GitHub Indicators as Threat Intel feed [sunburst-hunting/indicators](https://github.com/christian-taillon/sunburst-hunting/tree/main/indicators). A guide for doing so can be found [here](https://www.splunk.com/en_us/blog/security/how-do-i-add-covid-threat-intelligence-from-the-internet-to-enterprise-security.html).
2. Copy append content in savedsearches.conf into your local savedsearches.conf into desired Splunk app via ssh or, copy and paste contents after 'search =' to create each search manually. Schedule search window and schedueld time according to your environment.

        [Sunburst Bad Domain]
        action.email.useNSSubject = 1
        action.keyindicator.invert = 0
        action.makestreams.param.verbose = 0
        action.ms_teams_publish_to_channel = 1
        action.ms_teams_publish_to_channel.param.alert_ms_teams_activity_title = $name$  - $job.latestTime$ - $job.runDuration$
        action.ms_teams_publish_to_channel.param.alert_ms_teams_fields_list = url
        action.ms_teams_publish_to_channel.param.alert_ms_teams_fields_order = order_by_alpha
        action.nbtstat.param.verbose = 0
        action.notable.param.verbose = 0
        action.nslookup.param.verbose = 0
        action.ping.param.verbose = 0
        action.risk.param.verbose = 0
        action.threat_add.param.verbose = 0
        alert.track = 0
        cron_schedule = 0 23 17 1 1
        description = Sunburst Bad Domain from Web Data Model
        dispatch.latest_time = 1608102000
        display.events.fields = ["vendor_product","action","file_name","event.DetectDescription","host","sAMAccountName","dNSHostName","nt_host","search_name","DetectedBy","DeviceName","EventName","FilePath","FileType","Found","SHA256","ThreatClassification","subject","event.Objective","event.DetectName","event.Tactic","event.Technique","category","signature_version","signature","url"]display.events.type = table
        display.general.type = statistics
        display.page.search.mode = fast
        display.page.search.tab = statistics
        display.visualizations.charting.chart = area
        display.visualizations.show = 0
        enableSched = 1
        request.ui_dispatch_app = search
        request.ui_dispatch_view = search
        schedule_window = 1440
        search = | tstats `summariesonly` count from datamodel=Web.Web by Web.url\
        | rename Web.url as url \
        | stats count as "occurances" by url \
        | append \
            [| inputlookup append=t sunburst-domain \
            | rename Domain as domain \
            | inputlookup append=T ip_intel where threat_key=sunburst_domains \
            | dedup domain\
            | eval isBad = "TRUE" \
            | eval url = domain + "/"] \
        | stats count values(isBad) as "Bad domain found?"  by url\
        | search count >= 2\
        | outputcsv sunburst_bad_domain.csv

        [Sunburst Bad FileHash]
        action.email.useNSSubject = 1
        action.keyindicator.invert = 0
        action.makestreams.param.verbose = 0
        action.nbtstat.param.verbose = 0
        action.notable.param.verbose = 0
        action.nslookup.param.verbose = 0
        action.ping.param.verbose = 0
        action.risk.param.verbose = 0
        action.threat_add.param.verbose = 0
        alert.track = 0
        description = Bad file hash from Malware datamodel
        dispatch.latest_time = 1608102000
        display.events.fields = ["host","source","sourcetype","src_ip","dest_ip"]
        display.general.type = statistics
        display.page.search.tab = statistics
        display.visualizations.chartHeight = 278
        display.visualizations.charting.chart = line
        display.visualizations.show = 0
        request.ui_dispatch_app = search
        request.ui_dispatch_view = search
        search = | from datamodel:Malware \| stats count by file_hash \
        | append \
            [| inputlookup append=T file_intel where threat_key=sunburst-sha256 \
            | eval isBad = "TRUE" \
            | table description file_hash isBad threat_key ] \
        | stats count values(isBad) as "Bad hash found?" by file_hash\
        | search count >= 2

        [Sunburst Bad IP Search - Source]
        action.email.useNSSubject = 1
        action.keyindicator.invert = 0
        action.makestreams.param.verbose = 0
        action.ms_teams_publish_to_channel = 1
        action.ms_teams_publish_to_channel.param.alert_ms_teams_activity_title = $name$ - $job.latestTime$ - $job.runDuration$
        action.ms_teams_publish_to_channel.param.alert_ms_teams_fields_list = src
        action.ms_teams_publish_to_channel.param.alert_ms_teams_fields_order = order_by_alpha
        action.nbtstat.param.verbose = 0
        action.notable.param.verbose = 0
        action.nslookup.param.verbose = 0
        action.ping.param.verbose = 0
        action.risk.param.verbose = 0
        action.threat_add.param.verbose = 0
        alert.track = 0
        cron_schedule = 0 23 16 1 1
        description = Search to look for bad IP address sources network traffic datamodel
        dispatch.latest_time = 1608102000
        display.events.fields = ["vendor_product","action","file_name","event.DetectDescription","host","sAMAccountName","dNSHostName","nt_host","search_name","DetectedBy","DeviceName","EventName","FilePath","FileType","Found","SHA256","ThreatClassification","subject","event.Objective","event.DetectName","event.Tactic","event.Technique","category","signature_version","signature"]
        display.events.type = table
        display.general.type = statistics
        display.page.search.tab = statistics
        display.visualizations.charting.chart = area
        display.visualizations.show = 0
        enableSched = 1
        request.ui_dispatch_app = search
        request.ui_dispatch_view = search
        schedule_window = 1440
        search = | from datamodel:"Network_Traffic"."All_Traffic" \
        | where NOT src like "192.168.%" AND NOT src like "10.%" AND NOT src like "172.%" \
        | append \
            [| inputlookup append=T ip_intel where threat_key=sunburs_ipv4_avsmcloud_root_aRecords \
            | inputlookup append=T ip_intel where threat_key=sunburst_ipv4_c2 \
            | inputlookup append=T ip_intel where threat_key=sunburst_ipv4_dga \
            | eval isBad = "TRUE" \
            | rename ip as src \
            | table description src isBad threat_key ] \
        | stats count values(isBad) as "Bad IP found?" by src \
        | outputl sunburst_bad_ip_source.csv

        [Sunburst Bad IP Search]
        action.email.useNSSubject = 1
        action.keyindicator.invert = 0
        action.makestreams.param.verbose = 0
        action.ms_teams_publish_to_channel = 1
        action.ms_teams_publish_to_channel.param.alert_ms_teams_activity_title = $name$ - job.runDuration$ - $job.latestTime$,
        action.ms_teams_publish_to_channel.param.alert_ms_teams_fields_list = dest
        action.ms_teams_publish_to_channel.param.alert_ms_teams_fields_order = order_by_alpha
        action.nbtstat.param.verbose = 0
        action.notable.param.verbose = 0
        action.nslookup.param.verbose = 0
        action.ping.param.verbose = 0
        action.risk.param.verbose = 0
        action.threat_add.param.verbose = 0
        alert.track = 0
        cron_schedule = 0 23 15 1 1
        description = Search to look for bad IP address destinations in datamodel
        dispatch.earliest_time = -1y@y
        dispatch.latest_time = @y
        display.events.fields = ["vendor_product","action","file_name","event.DetectDescription","host","sAMAccountName","dNSHostName","nt_host","search_name","DetectedBy","DeviceName","EventName","FilePath","FileType","Found","SHA256","ThreatClassification","subject","event.Objective","event.DetectName","event.Tactic","event.Technique","category","signature_version","signature"]
        display.events.type = table
        display.general.type = statistics
        display.page.search.tab = statistics
        display.visualizations.charting.chart = area
        display.visualizations.show = 0
        enableSched = 1
        request.ui_dispatch_app = search
        request.ui_dispatch_view = search
        schedule_window = 1440
        search = | from datamodel:"Network_Traffic"."All_Traffic" \
        | where NOT dest like "192.168.%" AND NOT dest like "10.%" AND NOT dest like "172.%" \
        | stats count by dest \
        | append \
            [| inputlookup append=T ip_intel where threat_key=sunburs_ipv4_avsmcloud_root_aRecords \
            | inputlookup append=T ip_intel where threat_key=sunburst_ipv4_c2 \
            | inputlookup append=T ip_intel where threat_key=sunburst_ipv4_dga \
            | eval isBad = "TRUE" \
            | rename ip as dest \
            | table description dest isBad threat_key ] \
        | stats count values(isBad) as "Bad IP found?" by dest  \
        | search count >= 2 \
        | outputcsv sunburst_bad_ip.csv


3. Go to 'User Interface' -> 'Views' -> 'New View' and paste  sunburst-hunting-dashboard.xml into new view.

        <dashboard theme="dark">
          <label>Sunburst UNC2452 Network</label>
          <description>An attempt to high level, check for indicators of what type of victim we are (stage 1, stage 2, stage 3)</description>
          <row>
            <panel>
              <title>https://github.com/christian-taillon/sunburst-hunting</title>
            </panel>
          </row>
          <row>
            <panel>
              <title>Sunburst Domains - Github</title>
              <table>
                <title>High Confidence</title>
                <search>
                  <query>| inputlookup append=T ip_intel where threat_key=sunburst_domains

        | table description domain threat_key</query>
                  <earliest>-15m</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
              </table>
            </panel>
            <panel>
              <title>Sunburst IPs - Github</title>
              <table>
                <title>High Confidence</title>
                <search>
                  <query>| inputlookup append=T ip_intel where threat_key=sunburs_ipv4_avsmcloud_root_aRecords
        | inputlookup append=T ip_intel where threat_key=sunburst_ipv4_c2
        | table description ip threat_key</query>
                  <earliest>-15m</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
                <option name="refresh.display">progressbar</option>
              </table>
            </panel>
            <panel>
              <title>Sunburst DGA IP - Github</title>
              <table>
                <title>High Confidence</title>
                <search>
                  <query>| inputlookup append=T ip_intel where threat_key=sunburst_ipv4_dga
        | table description ip threat_key</query>
                  <earliest>-15m</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
              </table>
            </panel>
          </row>
          <row>
            <panel>
              <title>Domains (including others DGA)</title>
              <viz type="status_indicator_app.status_indicator">
                <title>Low Confidence</title>
                <search>
                  <query>| inputlookup append=t sunburst-domain
        | rename Domain as domain
        | inputlookup append=T ip_intel where threat_key=sunburst_domains
        | stats dc(domain)</query>
                  <earliest>0</earliest>
                  <latest></latest>
                </search>
                <option name="drilldown">none</option>
                <option name="refresh.display">progressbar</option>
                <option name="status_indicator_app.status_indicator.colorBy">static_color</option>
                <option name="status_indicator_app.status_indicator.fillTarget">text</option>
                <option name="status_indicator_app.status_indicator.fixIcon">globe</option>
                <option name="status_indicator_app.status_indicator.icon">fix_icon</option>
                <option name="status_indicator_app.status_indicator.precision">0</option>
                <option name="status_indicator_app.status_indicator.showOption">1</option>
                <option name="status_indicator_app.status_indicator.staticColor">#555</option>
                <option name="status_indicator_app.status_indicator.useColors">true</option>
                <option name="status_indicator_app.status_indicator.useThousandSeparator">true</option>
              </viz>
            </panel>
            <panel>
              <title>Distinct IP Addresses</title>
              <viz type="status_indicator_app.status_indicator">
                <title>Low Confidence</title>
                <search>
                  <query>| inputlookup append=t sunburst-ip
        | inputlookup append=T ip_intel where threat_key=sunburs_ipv4_avsmcloud_root_aRecords
        | inputlookup append=T ip_intel where threat_key=sunburst_ipv4_c2
        | inputlookup append=T ip_intel where threat_key=sunburst_ipv4_dga
        | rename ip as 'ip_address'
        | rename IP as 'ip_address'
        | stats dc('ip_address')</query>
                  <earliest>-24h@h</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
                <option name="refresh.display">progressbar</option>
                <option name="status_indicator_app.status_indicator.colorBy">static_color</option>
                <option name="status_indicator_app.status_indicator.fillTarget">text</option>
                <option name="status_indicator_app.status_indicator.fixIcon">server</option>
                <option name="status_indicator_app.status_indicator.icon">fix_icon</option>
                <option name="status_indicator_app.status_indicator.precision">0</option>
                <option name="status_indicator_app.status_indicator.showOption">1</option>
                <option name="status_indicator_app.status_indicator.staticColor">#555</option>
                <option name="status_indicator_app.status_indicator.useColors">true</option>
                <option name="status_indicator_app.status_indicator.useThousandSeparator">true</option>
              </viz>
            </panel>
          </row>
          <row>
            <panel>
              <table>
                <title>Sunurst IP - Dest</title>
                <search>
                  <query>| inputcsv sunburst_bad_ip.csv</query>
                  <earliest>-24h@h</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
              </table>
            </panel>
            <panel>
              <table>
                <title>Sunburst IP - Source</title>
                <search>
                  <query>| inputlookup sunburst_bad_ip_source.csv</query>
                  <earliest>-24h@h</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
              </table>
            </panel>
          </row>
          <row>
            <panel>
              <table>
                <title>Sunburst Domain</title>
                <search>
                  <query>| inputcsv sunburst_bad_domain.csv</query>
                  <earliest>-24h@h</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
              </table>
            </panel>
          </row>
          <row>
            <panel>
              <table>
                <title>Sunburst FileHash - Github</title>
                <search>
                  <query>| inputlookup append=T file_intel where threat_key=sunburst-sha256

        | table description file_hash threat_key</query>
                  <earliest>-15m</earliest>
                  <latest>now</latest>
                </search>
                <option name="drilldown">none</option>
                <option name="refresh.display">progressbar</option>
              </table>
            </panel>
            <panel>
              <table>
                <title>Sunburst Bad FileHash</title>
                <search ref="Sunburst Bad FileHash"></search>
                <option name="drilldown">none</option>
              </table>
            </panel>
          </row>
        </dashboard>


4. Go to 'User Interface' -> 'Navigation Menu' -> default and add your view to navigate to it while in the Splunk app.
        <view name="sunburst" />
