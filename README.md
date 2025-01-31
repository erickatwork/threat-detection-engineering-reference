# Threat Detection Engineering Reference

Frameworks, tools, and resources I find useful as a Threat Detection / Incident Response professional. Feel free to contribute.

## Table of Contents

* [Frameworks](#frameworks)
  * [Incident Response Lifecycle](#incident-response-lifecycle)
  * [Cyber Kill Chain](#cyber-kill-chain)
    * [Courses of Action Matrix](#courses-of-action-matrix)
  * [Pyramid of Pain](#pyramid-of-pain)
  * [1-10-60 Rule](#1-10-60-rule)
  * [Cybersecurity Defense Maturity Scorecard](#cybersecurity-defense-maturity-scorecard)
  * [Detection Engineering Maturity Matrix](#detection-engineering-maturity-matrix)
  * [ATT&CK](#attck)
  * [DeTT&CT](#dettct)
  * [Detections-as-Code (DaC)](#detections-as-code-dac)
  * [Distributed Alerting (DA)](#distributed-alerting-da)
  * [Risk-Based Alerting (RBA)](#risk-based-alerting-rba)
  * [Purple Teaming](#purple-teaming)
  * [Data Science](#data-science)
  * [Threat Modeling](#threat-modeling)
  * [Threat Inteligence](#threat-inteligence)
* [Detection Rules / Signatures](#detection-rules--signatures)
* [Notes](#notes)

## Frameworks

### Incident Response Lifecycle

![sans-incident-response-plan.jpg](images/sans-incident-response-plan.jpg)

[SANS](docs/sans-incident-handlers-handbook.pd) outlines the 6 incident phases.

![nist-incident-response-lifecycle.jpg](images/nist-incident-response-lifecycle.jpg)

[NIST](docs/nist-incident-response-lifecycle.pdf) outlines 4 phases.

### Cyber Kill Chain

![killchain.png](images/cyberkillchain.png)

[Lockheed Martin](docs/LM-White-Paper-Intel-Driven-Defense.pdf) breaks down an intrusion into 7 well-defined phases, and can help identify patterns that link individual intrusions into broader campaigns. The 7 phases cover all of the stages of a single intrusion that — when completed successfully — leads to a compromise.

* Clearly defined linear sequence of phases (as opposed to ATT&CK).
* `Reconnaissance` and `Weaponization` are often ignored but can be valuable.

#### Courses of Action Matrix

![Lockheed Martin](images/courseofactionmatrix.png)

Part of the Cyber Kill Chain. Defenders can measure the performance as well as the effectiveness of these actions, and plan investment roadmaps to rectify any capability gaps

* Valuable tool in evaluating capabilities and gaps.

### Pyramid of Pain

![Pyramid-of-Pain-v2.png](images/Pyramid-of-Pain-v2.png)

[David J Bianco](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) shows the relationship between the types of indicators you might use to detect an adversary's activities and how much pain it will cause them when you are able to deny those indicators to them.

* Pain is a two-way street for both the adversary and analyst. For the analyst, hash detections (atomic) are _trivial_ to write, and TTP detections (behavioral) are _tough_ to write.
* Atomic may offer higher confidence than behavioral detections, but behavioral detections offer more longevity.
* Useful to keep in mind when prioritizing detection rules.

### 1-10-60 Rule

[CrowdStrike](https://www.crowdstrike.com/blog/first-ever-adversary-ranking-in-2019-global-threat-report-highlights-the-importance-of-speed/) investigated, the average “breakout time” in 2017 was one hour and 58 minutes. Breakout time indicates how long it takes for an intruder to jump off the initial system (“beachhead”) they have compromised and move laterally to other machines within the network.

* 1 minute to detect, 10 minutes to investigate and 60 minutes to remediate.
* Useful to keep in mind when discussing ingest lag, working hours, and on-call.

### Cybersecurity Defense Maturity Scorecard

![defense-maturity-scorecard.jpg](images/defense-maturity-scorecard.jpg)

![defense-maturity-scorecard-score.png](images/defense-maturity-scorecard-score.png)

[Not-Sure-Who-Invented-This](Scorecard_Cybersecurity-Defense-Maturity-Evaluation.pdf) defines cybersecurity maturity across key domains.

* Decent tool for board maturity assessment

### Detection Engineering Maturity Matrix

![detection-maturity-matrix.png](images/detection-maturity-matrix.png)

* [Github](https://github.com/k-bailey/detection-engineering-maturity-matrix) & [detectionengineering.io](https://detectionengineering.io)
* [Article](https://kyle-bailey.medium.com/detection-engineering-maturity-matrix-f4f3181a5cc7) and [SANS Blue Team Summit Talk](https://www.youtube.com/watch?v=Dxccs8UDu6w&list=PLs4eo9Tja8biPeb2Wmf2H6-1US5zFjIxW&index=11)
* Converted to [Google Sheets](https://docs.google.com/spreadsheets/d/13hKfYXk1t1tfzsz59GsIOAcWen4QakUgj1OznZz-eHE/edit?usp=sharing)

### ATT&CK

[MITRE](https://attack.mitre.org/) ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. Enough gas been written on this.

### DeTT&CT

[Rabobank CDC](https://github.com/rabobank-cdc/DeTTECT) DeTT&CT aims to assist blue teams in using ATT&CK to score and compare data log source quality, visibility coverage, detection coverage, and threat actor behaviors.

### Detections-as-Code (DaC)

The principle of infrastructure-as-code but for detections. This allows you to version control detections and apply the same CI/CD principles to your detections as you do to your infrastructure.

* [Splunk](https://www.splunk.com/en_us/blog/security/ci-cd-detection-engineering-splunk-security-content-part-1.html) has a open-source project called [Splunk Security Content](https://github.com/splunk/security_content)
- Elastic has this open-source project called [Detection Rules for Elastic Security](https://github.com/elastic/detection-rules)
* Carta released their own tool called [Krang](https://github.com/carta/krang)

### Distributed Alerting (DA)

Popularized by Slack in this [blog post](https://slack.engineering/distributed-security-alerting/). The concept is to shift the burden of alert triage from Analyst to the relevant teams. Additional verification can be accomplished with 2FA.

* Great for misconfiguration-type alerts e.g. internet exposed server, compliance requirements, RBAC.

### Risk-Based Alerting (RBA)

![risk-based-alerting.png](images/risk-based-alerting.png)

Risk-based alerting (RBA) provides teams with a unique opportunity to pivot resources from traditionally reactive functions to proactive functions in the SOC.Apr 18, 2023
Detection tagged with observations and metadata to produce a score. Alerts are then correlated by some grouping e.g. user, IP, source. Then alert if the correlated alerts are above a certain score.

* [Splunk article](https://www.splunk.com/en_us/blog/security/risk-based-alerting-the-new-frontier-for-siem.html)
* [Video](https://conf.splunk.com/files/2018/recordings/say-goodbye-to-your-sec1479.mp4)

### Purple Teaming

Purple teaming to create/inspire detections.

* Tool [atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
* Tool [stratus-red-team](https://github.com/DataDog/stratus-red-team)

### Data Science

* Conference talk by [Strip](https://www.youtube.com/watch?v=-9BfXMYn0wk)

### Threat Modeling

Threat modeling works to identify, communicate, and understand threats and mitigations within the context of protecting something of value.

* Article [owasp](https://owasp.org/www-community/Threat_Modeling)
* Article by [infosecinstitute](https://resources.infosecinstitute.com/topic/top-threat-modeling-frameworks-stride-owasp-top-10-mitre-attck-framework/)

### Threat Inteligence

Threat intelligence is data that is collected, processed, and analyzed to understand a threat actor’s motives, targets, and attack behaviors. Threat intelligence enables us to make faster, more informed, data-backed security decisions and change their behavior from reactive to proactive in the fight against threat actors.

* Article by [crowdstrike](https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/)

## Detection Rules / Signatures

* [SigmaHQ](https://github.com/SigmaHQ/sigma/tree/master/rules)
* [Mitre](https://car.mitre.org/analytics/)
* [Splunk](https://github.com/splunk/security_content)
* [Elastic](https://github.com/elastic/detection-rules/tree/main/rules)
* [Datadoghq](https://docs.datadoghq.com/security_platform/default_rules/)
* [Streamalert](https://github.com/airbnb/streamalert/tree/master/rules/community)
* [Azure](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions)
* [Okta](https://sec.okta.com/shareddetections)
* MacOS [LooBins macOS Binaries](https://www.loobins.io/)

## Resources
* Detection Engineering
  * https://github.com/infosecB/awesome-detection-engineering
  * https://github.com/gracenolan/Notes/blob/master/interview-study-notes-for-security-engineering.md
  * https://scrty.io/
* IP/URL
  * https://talosintelligence.com/reputation_center
  * https://radar.cloudflare.com/scan
  * https://whois.domaintools.com/
  * https://virustotal.com/
  * https://www.maxmind.com/en/geoip-databases
  * https://urlscan.io/
* Browser Extension
  * https://crxcavator.io/
* OSINT
  * https://start.me/p/L1rEYQ/osint4all
  * https://urlscan.io/ 

## Notes

* Indicator types
  * Atomic - Atomic indicators are those which cannot be broken down into smaller parts and retain their meaning in the context of an intrusion. Typical examples here are IP addresses, email addresses, and vulnerability identifiers.
  * Computed - Computed indicators are those which are derived from data involved in an incident. Common computed indicators include hash values and regular expressions.
  * Behavioral - Behavioral indicators are collections of computed and atomic indicators, often subject to qualification by quantity and possibly combinatorial logic. An example would be a statement such as ”the intruder would initially use a backdoor which generated network traffic matching [regular expression] at the rate of [some frequency] to [some IP address], and then replace it with one matching the MD5 hash [value] once access was established.”
