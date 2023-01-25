import json
import pandas as pd
import plotly.graph_objects as go
import plotly.offline as offline
import argparse

import bs4

# made a couple of changes to the original script to make it work with the new json format.
# commented out the secrets line of code prisma doesnt scan for secrets i guess.
# changes are a bit messy while trying to figure it out.

def read_json(path: str):
    f = open(path)
    data = json.load(f)
    f.close()
    return data

def get_vulnerabilities (data: dict):
    vulnerabilities = []
    # Iterate thought the results list
    for item in data.get("results"):
        vulns_json = item.get("vulnerabilities")
        packages_json = item.get("packages")
        
        for vuln in vulns_json:

            data_vuln = {
                'Type': next((pkg.get("type") for pkg in packages_json if pkg['name'] == vuln.get('packageName')), None),
                'Severity': vuln.get('severity').upper(),
                'Package': vuln.get('packageName'),
                # 'Version': vuln.get('packageVersion'),
                'CVE': '<a href="' + vuln.get('link') + '">' + vuln.get('id') + '</a>',
                # 'Fixed Status': fixedStatus,
                # 'Risk factors': next((risk for risk in vuln.get('riskFactors') if vuln.get('riskFactors') != None ), None),
                'Risk factors': '-' if vuln.get('riskFactors') is None else " ".join(vuln.get('riskFactors')),
                'Description': vuln.get('description'),
            }
            vulnerabilities.append(data_vuln)


    # if data.get(type) is None:
    #     print("We do not have " + type + " vulnerabilities")
    #     return None
    # else:
    #     vulnerabilities = []
      
    #     for item in data.get(type):
    #         # Path value!!  not sure if i need a path.
    #         if item.get('path') == None:
    #             path = '-'
    #         else: 
    #             path = item.get('path')

    #         for vuln in item.get('vulnerabilities'):
    #             # Fixed Version value
    #             if vuln.get('status') == None:
    #                 fixedStatus = '-'
    #             else: 
    #                 fixedStatus = vuln.get('status')

    #         # i did this first to get type located in packages not sure if this is the right way or the second way is better.
    #         # for package in item.get('packages'):
    #         #     if package.get('type') == None:
    #         #         type = '-'
    #         #     else:
    #         #         type = package.get('type')
    #             data_vuln = {
    #                 # 'Type': type,
    #                 'Type': data.get("packages").get("type"),
    #                 'Severity': vuln.get('severity'),
    #                 'Name': vuln.get('packageName'),
    #                 'Version': vuln.get('packageVersion'),
    #                 'CVE': vuln.get('id'),
    #                 'CVSS': vuln.get('cvss'),
    #                 'Fixed Status': fixedStatus,
                    
    #                 'Link': '<a href="' + vuln.get('link') + '">More information</a>'
    #             }
    #             vulnerabilities.append(data_vuln)

    return vulnerabilities

def generate_table_figure(data:dict, table_data: list, output_file: str):
    layout_title = set_report_title (data)

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

def set_report_title (data:dict):
    title = "<b>Prismacloud Scanning</b><br>"

    container_images = [image.get("name") for image in data.get("results")]
    scan_results = [image.get("vulnerabilityScanPassed") for image in data.get("results")]

    for (image, result) in zip(container_images, scan_results):
        title = title + "<b> - Image: " + image + "</b>, "

        if result is False:
            title = title + "<b>Scan result: </b><span style='color:red'>FAILED</span>. Container image does not meet policy requirements<br>"

        if result is True:
            title = title + "<b>Scan result: </b><span style='color:green'>PASSED</span>. Container image meets policy requirements<br>"

    return title

def parse_arguments():
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-i", "--input-file", type=str, required=True, help='JSON file with prismacloud results')
    argParser.add_argument("-o", "--output-file", type=str, default='prismacloud_scanning_results.html', help="HTML output file")

    args = argParser.parse_args()

    return args.input_file,args.output_file

def main():

    input_file,output_file = parse_arguments()

    json_data = read_json(input_file)
    vulns = get_vulnerabilities (json_data)
    

    # if vuln == [] and secrets == None:
    #     print("\nCongratulations!!! The container image does not have vulnerabilities")
    # else:
    #     table_data = merge_vuln_secrets (vuln, secrets)
    generate_table_figure( json_data, vulns,  output_file )

    # Add logo to the repo

    # load the file
    with open(output_file) as inf:
        txt = inf.read()
        soup = bs4.BeautifulSoup(txt, "lxml")

    # # create new link
    new_image = soup.new_tag('img', src="https://static.vecteezy.com/system/resources/previews/003/554/120/original/modern-wavy-lines-paper-cut-style-yellow-color-banner-design-free-vector.jpg", alt="W3Schools.com", style="width:1200px;height:128px;")
    # # insert it into the document
    soup.body.insert(0, new_image)
    # soup.body.append(new_image)
    

    # # save the file again
    with open(output_file, "w") as outf:
        outf.write(str(soup))

if __name__ == '__main__':
    main()