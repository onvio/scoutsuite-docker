import json
import os
import argparse
import logging
from ScoutSuite.__main__ import run

def main(): 
    parser = argparse.ArgumentParser(description='Automated ScoutSuite Docker scanner')
    parser.add_argument('--aws-access-key-id', action="store", dest="access_key_id", default=None)
    parser.add_argument('--aws-secret-access-key', action="store", dest="access_key_secret", default=None)
    parser.add_argument('--azure-client-id', action="store", dest="client_id", default=None)
    parser.add_argument('--azure-client-secret', action="store", dest="client_secret", default=None)
    parser.add_argument('--report-name', action="store", dest="report_name")
    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='[%Y-%m-%d %H:%M:%S]', level=logging.INFO)
    logging.debug(f"Args: {args}")

    scantype = None
    if args.access_key_id and args.access_key_secret:
        scantype = "aws"
    elif args.client_id and args.client_secret:
        scantype = "azure"

    if not scantype:
        logging.error("Specify credentials for your provider")
        parser.print_help()
        exit()

    logging.info(f"Starting scantype: {scantype}")

    if not args.report_name:
        args.report_name = f"{scantype}"
    report_path = "/var/reports/"

    run(scantype,
        # AWS
        profile=None,
        aws_access_key_id=args.access_key_id,
        aws_secret_access_key=args.access_key_secret,
        aws_session_token=None,
        # Azure
        user_account=False,
        user_account_browser=False,
        cli=False, msi=False, service_principal=False, file_auth=None,
        client_id=None, client_secret=None,
        username=None, password=None,
        tenant_id=None,
        subscription_ids=None, all_subscriptions=None,
        # GCP
        service_account=None,
        project_id=None, folder_id=None, organization_id=None, all_projects=False,
        # Aliyun
        access_key_id=None, access_key_secret=None,
        # General
        report_name=args.report_name, report_dir=report_path,
        timestamp=False,
        services=[], skipped_services=[], list_services=None,
        result_format='json',
        database_name=None, host_ip='127.0.0.1', host_port=8000,
        max_workers=5,
        regions=[],
        excluded_regions=[],
        fetch_local=False, update=False,
        max_rate=None,
        ip_ranges=[], ip_ranges_name_key='name',
        ruleset='default.json', exceptions=None,
        force_write=True,
        debug=False,
        quiet=False,
        log_file=None,
        no_browser=False,
        programmatic_execution=True)

    scoutsuite_json_path = os.path.join(report_path, "scoutsuite-results", f"scoutsuite_results_{args.report_name}.js")
    output_path = os.path.join(report_path, "report.json")
    report_json = parse_report(scoutsuite_json_path)
    write_report(report_json, output_path)

def write_report(report_json, output_path):
    logging.info(f"Writing report: {output_path}")
    with open(output_path, 'w') as outfile:
        json.dump(report_json, outfile)

def parse_report(report_path):
    logging.info(f"Parsing report: {report_path}")
    json_report = load_json(report_path)
    qt_report = {
        "vulnerabilities": []
    }
    severity_mapping = {
        "warning": "medium",
        "danger": "high"
    }

    # Report findings
    for service in json_report["services"].items():
        for finding in service[1]["findings"].items():
            flagged_items = int(finding[1]["flagged_items"])
            if flagged_items > 0:
                title = finding[1]["description"]
                if flagged_items > 1:
                    title = f"{title} ({flagged_items} instances)"
                issue = {
                    "title": title,
                    "description": finding[1]["rationale"],
                    "severity": severity_mapping.get(finding[1]["level"])
                }
                qt_report['vulnerabilities'].append(issue)
                
    # Report external attack surface
    for service_group in json_report["service_groups"].items():
        for item in service_group[1]["summaries"]["external_attack_surface"].items():
            issue = {
                "title": "External exposed EC instance",
                "description": f'{item[1]["PublicDnsName"]} [{item[0]}] ({item[1]["InstanceName"]})',
                "severity": "medium"
            }
            qt_report['vulnerabilities'].append(issue)

    return qt_report

def load_json(path):
    logging.info(f"Loading json from: {path}")
    with open(path) as f:
        json_payload = f.readlines()
        json_payload.pop(0)
        json_payload = ''.join(json_payload)
        json_file = json.loads(json_payload)
        return json_file

if __name__ == "__main__":
    main()