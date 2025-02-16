## YARCAST – YARA Collection, Aggregation, Scanning, and Threat detection

This is a command line tool that simplifies collecting and scanning with public YARA repositories.

The yarscan collector fetches and compiles YARA rules based on a list of public repositories or local signature folders. It makes sure to avoid duplicates and exclude rules that have very small patterns. From experience the performance will be unbearable without exclusion of these rules.

The yarscan scanner will use all the collected yara rules to scan a file or files in a folder and display the results sorted by repository.

Both scripts make use of a blocklist, where you can put rules that annoy you due to logical errors, FPs or performance issues.

## Install requirements

```pip install -r requirements.txt```

## Step 1 Collecting and compiling rules

Firstly, fill in a list of public repositories or local folders with YARA rules (see below). 

Then run `python yarcast_collect.py` and wait. 

### full_checkout_repos.csv

Each repository in here will be fully cloned and searched for signatures.

Use the format `your_personal_repo_name, repo_url`

### sparse_checkout_repos.csv

For each respository in here, YARCAST will only download a specific folder.

Use the format `your_personal_repo_name, repo_url, folder, subfolder, subsubfolder, ...`

For example:

```
CAPE,https://github.com/ctxis/CAPE,data,yara,CAPE
```

### local_signatures_folders.csv

This will use a local path to a folder containing signatures.

Use the format `your_personal_repo_name, path`


## Step 2 Scanning

Now that all the rules have been compiled, scan a file (or folder) with:

```
python yarcast_scan.py -ab -a -s filename 
```

The switch -a will show the rule's authors. The switch -s will show the matched strings.

The switch -ab automatically puts rules on a blocklist if they cause problems.

You can also manually block rules either by adding them to `blocklist.txt` or by running

```
python yarcast_scan.py -b rulename
```

Next time you use yarcast_collect, the rule will also be excluded from compilation. You should do this if a rule causes performance issues. Without recompilation the rule will still be used for scanning but hidden from the output.