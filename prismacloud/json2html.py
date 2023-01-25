import json
import pandas as pd
import plotly.graph_objects as go
import plotly.offline as offline
import argparse

# made a couple of changes to the original script to make it work with the new json format.
# commented out the secrets line of code prisma doesnt scan for secrets i guess.
# changes are a bit messy while trying to figure it out.

# prismacloud vulnerabilities types
vuln_types = ["packages","applications","compliances","complianceDistribution","complianceScanPassed","vulnerabilities","vulnerabilityDistribution","vulnerabilityScanPassed","history","scanTime","scanID"]

def read_json(path: str):
    f = open(path)
    data = json.load(f)
    f.close()
    return data

# def merge_vuln_secrets (vuln: list, secrets: list):

#     # If there are vuln and secrets, merge both lists
#     if vuln == [] and secrets == None:
#         print("INFO: Lists can not be merged:\n" + 
#               "       + vuln: " + str(type(vuln)) + "\n" +
#               "       + secrets: " + str(type(secrets)))
#         return None
#     else:
#         if vuln == None:
#             table_data = secrets
#         elif secrets == None:
#             table_data = vuln

#         else:
#             table_data = vuln

#             for item in secrets:
#                 table_data.append(item)

    
#     return table_data

def get_vulnerabilities_by_type (data: dict, type: str):
    if data.get(type) is None:
        print("We do not have " + type + " vulnerabilities")
        return None
    else:
        vulnerabilities = []
      
        for item in data.get(type):
            # Path value!!  not sure if i need a path.
            if item.get('path') == None:
                path = '-'
            else: 
                path = item.get('path')

            for vuln in item.get('vulnerabilities'):
                # Fixed Version value
                if vuln.get('status') == None:
                    fixedStatus = '-'
                else: 
                    fixedStatus = vuln.get('status')

            # i did this first to get type located in packages not sure if this is the right way or the second way is better.
            # for package in item.get('packages'):
            #     if package.get('type') == None:
            #         type = '-'
            #     else:
            #         type = package.get('type')
                data_vuln = {
                    # 'Type': type,
                    'Type': data.get("packages").get("type"),
                    'Severity': vuln.get('severity'),
                    'Name': vuln.get('packageName'),
                    'Version': vuln.get('packageVersion'),
                    'CVE': vuln.get('id'),
                    'CVSS': vuln.get('cvss'),
                    'Fixed Status': fixedStatus,
                    
                    'Link': '<a href="' + vuln.get('link') + '">More information</a>'
                }
                vulnerabilities.append(data_vuln)

        return vulnerabilities

def get_vulnerabilities (data: dict):
    vulnerabilities=[]


    for vuln_type in vuln_types:
        vuln = get_vulnerabilities_by_type (data, vuln_type)
        if vuln is not None:
            for item in vuln:
                vulnerabilities.append(item)
        
    return vulnerabilities

# def get_secrets (data: dict):
#     secrets = []

#     if data.get("secrets") is None:
#         print("We do not have secrets")
#         return None
#     else:
#         for item in data.get("secrets"):
#                 data_secret = {
#                     'Type': 'secret',
#                     'Name': item.get('description'), 
#                     'Path': item.get('path'), 
#                     'Version': '-',
#                     'Fixed Version': 'Remove secret from container',
#                     'CVE': '-',
#                     'Severity': '-',
#                     'Source': '-'
#                 }
#                 secrets.append(data_secret)
#     return secrets

def generate_table_figure(data:dict, table_data: list, output_file: str):
    subtitle_result = set_report_result(data.get("vulnerabilityScanPassed"))
    container_image = data.get("results").get("name")
    distro = data.get("results").get("distro")

    layout_title = "<b>Prismacloud Scanning - Image: " + container_image + "</b><br>" +  "<br>" + subtitle_result + "<br>" + "<b>Distro:</b> " + distro + "<br>"

    df = pd.DataFrame.from_dict(table_data)

    fig = go.Figure(
        data = go.Table(
            header={
                'values': "<b>" + df.columns + "</b>"}, 
            cells={
                'values': df.T.values}
            ),
        layout=go.Layout(
            title=go.layout.Title(text=layout_title)
            )
        )


    fig.update_layout(
        updatemenus=[
            {
                'buttons': [
                    {
                        'label': c,
                        'method': 'update',
                        'args': [
                            {
                                'cells': {
                                    'values': df.T.values
                                    if c == 'All'
                                    else df.loc[df['Type'].eq(c)].T.values
                                }
                            }
                        ],
                    }
                    for c in ['All'] + df['Type'].unique().tolist()
                ]
            }
        ]
    )

    
    offline.plot(fig, filename = output_file, auto_open=False, show_link=False)

def set_report_result (scanning_status: str):
    if "false" in scanning_status:
        subtitle_result = "<b>Scan result:</b> <span style='color:red'>FAILED</span>"
        # Scan results: FAILED. Container image does not meet policy requirements

    if "true" in scanning_status:
        subtitle_result = "<b>Scan result:</b> <span style='color:green'>PASSED</span>"

    return subtitle_result


def parse_arguments():
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-i", "--input-file", type=str, required=True, help='JSON file with prismacloud results')
    argParser.add_argument("-o", "--output-file", type=str, default='prismacloud_scanning_results.html', help="HTML output file")

    args = argParser.parse_args()

    return args.input_file,args.output_file

def main():

    input_file,output_file = parse_arguments()

    json_data = read_json(input_file)
    vuln = get_vulnerabilities (json_data.get("results"))
    

    # if vuln == [] and secrets == None:
    #     print("\nCongratulations!!! The container image does not have vulnerabilities")
    # else:
    #     table_data = merge_vuln_secrets (vuln, secrets)
    generate_table_figure( json_data,  output_file )

if __name__ == '__main__':
    main()