# Usage
```yaml
- uses: wbd-streaming/infosec-pacsec-actions/prismacloud/scan@main
  with:
    # Prismacloud url to compute console
    # Example: ${{ secrets.CONTAINERSEC_CICD_PCC_CONSOLE_URL }}
    pcc_console_url: ''

    # Prismacloud service account ID
    # Example: ${{ secrets.CONTAINERSEC_CICD_PCC_USER }}
    pcc_user: ''

    # Prismacloud service account's secret
    # Example: ${{ secrets.CONTAINERSEC_CICD_PCC_PASS }}
    pcc_pass: ''

    # Image name, including the tag/digest, or path to file (.tar, .tar.gz or .tgz)
    # Example: 123456789123.dkr.ecr.us-east-1.amazonaws.com/hello-world:1.0
    image_name: ''

    # Tags to mark the scan with, can be KEY or KEY=VALUE (default [])
    # Example: scan_env=github,project=hello-world
    scan_tag: ''